// windows IATHook for kernelmode and usermode 
// by TinySec( root@tinysec.net )
// you can free use this code , but if you had modify , send a copy to to my email please.



/*
LONG IATHook
(
	__in void* pImageBase ,
	__in_opt char* pszImportDllName ,
	__in char* pszRoutineName ,
	__in void* pFakeRoutine ,
	__out HANDLE* Param_phHook
);

LONG UnIATHook( __in HANDLE hHook );

void* GetIATHookOrign( __in HANDLE hHook );
*/


//////////////////////////////////////////////////////////////////////////

#ifdef _RING0
	#include <ntddk.h>
	#include <ntimage.h>
#else
	#include <windows.h>
	#include <stdlib.h>
#endif //#ifdef _RING0


//////////////////////////////////////////////////////////////////////////

typedef struct _IATHOOK_BLOCK
{
	void*	pOrigin;

	void*	pImageBase;
	char*	pszImportDllName;
	char*	pszRoutineName;

	void*	pFake;
	
}IATHOOK_BLOCK;


//////////////////////////////////////////////////////////////////////////

void* _IATHook_Alloc(__in ULONG nNeedSize)
{
	void* pMemory = NULL;

	do 
	{
		if ( 0 == nNeedSize )
		{
			break;
		}
		
#ifdef _RING0
		pMemory = ExAllocatePoolWithTag( NonPagedPool , nNeedSize , 'iath' );

#else
		pMemory = malloc( nNeedSize );
#endif // #ifdef _RING0
		
		if ( NULL == pMemory )
		{
			break;
		}

		RtlZeroMemory( pMemory , nNeedSize );

	} while (FALSE);

	return pMemory;
}


ULONG _IATHook_Free(__in void* pMemory )
{

	do 
	{
		if ( NULL == pMemory )
		{
			break;
		}
		
#ifdef _RING0
		ExFreePool( pMemory );
		
#else
		free( pMemory );
#endif // #ifdef _RING0
		
		pMemory = NULL;
		
	} while (FALSE);
	
	return 0;
}

//////////////////////////////////////////////////////////////////////////
#ifdef _RING0


#ifndef LOWORD
	#define LOWORD(l)           ((USHORT)((ULONG_PTR)(l) & 0xffff))
#endif // #ifndef LOWORD


void*  _IATHook_InterlockedExchangePointer(__in void* pAddress , __in void* pValue )
{
	void*	pWriteableAddr=NULL;
	PMDL	pNewMDL = NULL;
	void*	pOld =  NULL;
	
	do 
	{
		if (  (NULL == pAddress)  )
		{
			break;
		}
		
		if ( !NT_SUCCESS(MmIsAddressValid(pAddress)) )
		{
			break;
		}
		
		pNewMDL = IoAllocateMdl(pAddress , sizeof(void*) , FALSE , FALSE , NULL);
		if (pNewMDL == NULL)
		{
			break;
		}
		
		__try
		{
			MmProbeAndLockPages(pNewMDL, KernelMode, IoReadAccess);
			
			pNewMDL->MdlFlags |= MDL_MAPPING_CAN_FAIL;
			
			pWriteableAddr = MmMapLockedPagesSpecifyCache(
					pNewMDL ,
					KernelMode ,
					MmNonCached ,
					NULL ,
					FALSE ,
					HighPagePriority 
			);
			
			MmProtectMdlSystemAddress(pNewMDL, PAGE_READWRITE);
			
			//pWriteableAddr = MmMapLockedPages(pNewMDL, KernelMode);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}
		
		if (pWriteableAddr == NULL) 
		{
			MmUnlockPages(pNewMDL);
			IoFreeMdl(pNewMDL);
			
			break;
		}
		
		pOld = InterlockedExchangePointer( pWriteableAddr , pValue);
		
		MmUnmapLockedPages(pWriteableAddr,pNewMDL);
		MmUnlockPages(pNewMDL);
		IoFreeMdl(pNewMDL);
		
	} while (FALSE);
	
	return pOld;
}


//////////////////////////////////////////////////////////////////////////
#else

void*  _IATHook_InterlockedExchangePointer(__in void* pAddress , __in void* pValue )
{
	void*	pWriteableAddr=NULL;
	void*	nOldValue =  NULL;
	ULONG	nOldProtect = 0;
	BOOL	bFlag = FALSE;
	
	do 
	{
		if (  (NULL == pAddress)  )
		{
			break;
		}
		
		bFlag = VirtualProtect( pAddress , sizeof(void*) , PAGE_EXECUTE_READWRITE , &nOldProtect );
		if ( !bFlag )
		{
			break;
		}
		pWriteableAddr = pAddress;
		
		nOldValue = InterlockedExchangePointer( pWriteableAddr , pValue );
		
		VirtualProtect( pAddress , sizeof(void*) , nOldProtect , &nOldProtect );
		
	} while (FALSE);
	
	return nOldValue;
}

#endif // #ifdef _RING0


LONG _IATHook_Single
(
	__in IATHOOK_BLOCK*	pHookBlock ,
	__in IMAGE_IMPORT_DESCRIPTOR*	pImportDescriptor ,
	__in BOOLEAN bHook
)
{
	LONG				nFinalRet = -1;

	IMAGE_THUNK_DATA*	pOriginThunk = NULL;
	IMAGE_THUNK_DATA*	pRealThunk = NULL;

	IMAGE_IMPORT_BY_NAME*	pImportByName = NULL;

	do 
	{
		pOriginThunk = (IMAGE_THUNK_DATA*)( (UCHAR*)pHookBlock->pImageBase + pImportDescriptor->OriginalFirstThunk );
		pRealThunk = (IMAGE_THUNK_DATA*)( (UCHAR*)pHookBlock->pImageBase + pImportDescriptor->FirstThunk );

		for ( ;  0 != pOriginThunk->u1.Function; pOriginThunk++ , pRealThunk++ )
		{
			if ( IMAGE_ORDINAL_FLAG == ( pOriginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ) )
			{
				if ( (USHORT)pHookBlock->pszRoutineName == LOWORD( pOriginThunk->u1.Ordinal) )
				{
					if ( bHook )
					{
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;
						_IATHook_InterlockedExchangePointer( (void**)&pRealThunk->u1.Function , pHookBlock->pFake );
					}
					else
					{
						_IATHook_InterlockedExchangePointer( (void**)&pRealThunk->u1.Function , pHookBlock->pOrigin );
					}

					nFinalRet = 0; 
					break;
				}
			}
			else
			{
				pImportByName = (IMAGE_IMPORT_BY_NAME*)( (char*)pHookBlock->pImageBase + pOriginThunk->u1.AddressOfData );

				if ( 0 == _stricmp( pImportByName->Name ,  pHookBlock->pszRoutineName ) )
				{	
					if ( bHook )
					{
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;
						_IATHook_InterlockedExchangePointer( (void**)&pRealThunk->u1.Function , pHookBlock->pFake );
					}
					else
					{
						_IATHook_InterlockedExchangePointer( (void**)&pRealThunk->u1.Function , pHookBlock->pOrigin );
					}

					nFinalRet = 0;

					break;
				}
			}

		}
		
	} while (FALSE);

	return nFinalRet;
}


LONG _IATHook_Internal( __in IATHOOK_BLOCK* pHookBlock , __in BOOLEAN bHook)
{
	LONG				nFinalRet = -1;
	LONG				nRet = -1;
	IMAGE_DOS_HEADER*	pDosHeader = NULL;
	IMAGE_NT_HEADERS*	pNTHeaders = NULL;

	IMAGE_IMPORT_DESCRIPTOR*	pImportDescriptor = NULL;
	char*						pszImportDllName = NULL;

	
	do 
	{
		if ( NULL == pHookBlock )
		{
			break;
		}
		
		pDosHeader = (IMAGE_DOS_HEADER*)pHookBlock->pImageBase;
		if ( IMAGE_DOS_SIGNATURE != pDosHeader->e_magic )
		{
			break;
		}
		
		pNTHeaders = (IMAGE_NT_HEADERS*)( (UCHAR*)pHookBlock->pImageBase + pDosHeader->e_lfanew );
		if ( IMAGE_NT_SIGNATURE != pNTHeaders->Signature )
		{
			break;
		}
		
		if ( 0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress )
		{
			break;
		}
		
		if ( 0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size )
		{
			break;
		}
		
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)( (UCHAR*)pHookBlock->pImageBase + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
		
		
		// Find pszRoutineName in every Import descriptor
		nFinalRet = -1;

		for (  ;  (pImportDescriptor->Name != 0 );  pImportDescriptor++ )
		{
			pszImportDllName = (char*)pHookBlock->pImageBase + pImportDescriptor->Name;

			if ( NULL != pHookBlock->pszImportDllName )
			{
				if ( 0 != _stricmp(pszImportDllName , pHookBlock->pszImportDllName) )
				{
					continue;
				}
			}
			
			nRet = _IATHook_Single(
				pHookBlock,
				pImportDescriptor,
				bHook
			);
			
			if ( 0 == nRet )
			{
				nFinalRet = 0;
				break;
			}
		}
			
	} while (FALSE);
	
	return nFinalRet;
}

LONG IATHook
(
	__in void* pImageBase ,
	__in_opt char* pszImportDllName ,
	__in char* pszRoutineName ,
	__in void* pFakeRoutine ,
	__out HANDLE* Param_phHook
)
{
	LONG				nFinalRet = -1;
	IATHOOK_BLOCK*		pHookBlock = NULL;
	
	
	do 
	{
		if ( (NULL == pImageBase) || (NULL == pszRoutineName) || (NULL == pFakeRoutine) )
		{
			break;
		}
		
		pHookBlock = (IATHOOK_BLOCK*)_IATHook_Alloc( sizeof(IATHOOK_BLOCK) );
		if ( NULL == pHookBlock )
		{
			break;
		}
		RtlZeroMemory( pHookBlock , sizeof(IATHOOK_BLOCK) );
		
		pHookBlock->pImageBase = pImageBase;
		pHookBlock->pszImportDllName = pszImportDllName;
		pHookBlock->pszRoutineName = pszRoutineName;
		pHookBlock->pFake = pFakeRoutine;
		
		__try
		{
			nFinalRet = _IATHook_Internal(pHookBlock , TRUE);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;
		}
		
	} while (FALSE);
	
	if ( 0 != nFinalRet )
	{
		if ( NULL != pHookBlock )
		{
			_IATHook_Free( pHookBlock );
			pHookBlock = NULL;
		}
	}

	if ( NULL != Param_phHook )
	{
		*Param_phHook = pHookBlock;
	}

	return nFinalRet;
}

LONG UnIATHook( __in HANDLE hHook )
{
	IATHOOK_BLOCK*		pHookBlock = (IATHOOK_BLOCK*)hHook;
	LONG				nFinalRet = -1;

	do 
	{
		if ( NULL == pHookBlock )
		{
			break;
		}
		
		__try
		{
			nFinalRet = _IATHook_Internal(pHookBlock , FALSE);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;
		}
			
	} while (FALSE);

	if ( NULL != pHookBlock )
	{
		_IATHook_Free( pHookBlock );
		pHookBlock = NULL;
	}

	return nFinalRet;
}

void* GetIATHookOrign( __in HANDLE hHook )
{
	IATHOOK_BLOCK*		pHookBlock = (IATHOOK_BLOCK*)hHook;
	void*				pOrigin = NULL;
	
	do 
	{
		if ( NULL == pHookBlock )
		{
			break;
		}
		
		pOrigin = pHookBlock->pOrigin;
			
	} while (FALSE);
	
	return pOrigin;
}



