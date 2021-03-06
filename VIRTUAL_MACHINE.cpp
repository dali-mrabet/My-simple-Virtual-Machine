*******************************************************
* written by : Mohamed ali Mrabet                     *
* facebook :   https://www.facebook.com/dali.mrabet.3 *
* Blog :       http://dali-mrabet1.rhcloud.com/       *
*                                                     *
*******************************************************

/*
    Copyright (C) <2015>  <Mohamed Ali Mrabet>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Psapi.h>



using namespace std ;

static int delta = 0 ;
static int PC = 0 ;


#pragma comment(linker,"/include:__tls_used")
#pragma section(".CRT$XLB",read)


void NTAPI ThreadLocalStorage(PVOID Module,DWORD Reason,PVOID Context)
{

    typedef NTSTATUS (NTAPI * FNtQueryInformationProcess)(HANDLE hProcess,ULONG InfoClass,PVOID Buffer,ULONG Length,PULONG ReturnLength);
    HANDLE isdebugged, MyVM = GetCurrentProcess();

    HMODULE ntdll = LoadLibraryA("ntdll.dll");

    FNtQueryInformationProcess myNtQueryInformationProcess = (FNtQueryInformationProcess  )GetProcAddress(ntdll,"NtQueryInformationProcess");

    myNtQueryInformationProcess(MyVM,7,&isdebugged,sizeof(HANDLE),NULL);

    if(isdebugged == (HANDLE)-1)

        ExitProcess(-1);
}

__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK Callbacks[]= {ThreadLocalStorage,NULL};



#define __TIMING_CHECK__ __asm    \
	{                             \
	 __asm pusha                  \
	 __asm xor eax , eax          \
	 __asm xor ecx , ecx          \
	 __asm rdtsc                  \
         __asm mov ebx , eax          \
	 __asm mov delta , edi        \
         __asm nop                    \
         __asm sub edx , ebx          \
         __asm nop                    \
	 __asm rdtsc                  \
	 __asm sub eax , ebx          \
	 __asm mov delta , eax        \
	 __asm popa                   \
}				      \
   if(delta >= 0x100)                 \
   exit(-1);                          \
   else 		              \
   delta = 0 ;




#define MOV  1
#define ADD  2
#define SUB  3
#define XOR  4
#define PUSH 5
#define POP  6
#define JMP  7
#define MUL  8
#define AND  9
#define OR   0xA
#define CALL 0xB
#define RET  0xC
#define CMP  0xD
#define JE   0xE
#define JA   0xF
#define JL   0x0
#define HALT 0xFFFFFFFF

//---- Indication Bytes !!
#define IS_REG 1
#define IS_VALUE 2  // immediate value 
#define IS_DEREFERENCE 3 // dereferences a pointer e.g "mov eax , [edx]" where edx holds a pointer !! 


static enum RandomValues
{
    BYTE_OVERFLOW = 1 ,
    INVALID_INSTRUCTION = 2 ,
    UNEXPECTED_LONG_JUMP = 3 ,
    EMPTY_STACK = 4 ,
    INVALID_RETURN_ADDRESS = 5,
    ZERO_FLAG = 2 ,
    SIGN_FLAG = 3 ,
    OVERFLOW_FLAG = 1 ,
    EFLAGS_MASK = 0x00000001

};

typedef struct
{
    char   OpCode ;
    char   DestType;
    char   SrcType ;
    char   DstReg ;
    char   SrcReg ;
    char   Displacement ;
    char   ByteValue ;

} VIRTUAL_INSTRUCTION;


typedef struct Stack
{
    int item ;
    bool IsEmpty ;
    Stack * Previous_Stack_Frame ;

} VIRTUAL_STACK ;


typedef struct
{
    int R1 ;
    int R2 ;
    int R3 ;
    int R4 ;
    int R5 ;
    int R6 ;
    int R7 ;
    int R8 ;
    VIRTUAL_STACK *SP ;// stack pointer
    VIRTUAL_STACK *BP ;// base  pointer

} VIRTUAL_REGISTERS ;


typedef struct
{

    int                * BaseAddr ;      // Starting address !!
    VIRTUAL_REGISTERS  * Regs     ;      // RegisterS
    int                * ProgramCounter ;//Instruction pointer  !!
    int                  Eflags ; // Flag Register !  |S|Z|O|nothing| 4bit-long
    VIRTUAL_STACK      * VStack ;

} VIRTUAL_CPU;


class VIRTUAL_MACHINE
{

private :

    VIRTUAL_INSTRUCTION * Instruction ;
    VIRTUAL_CPU * Processor ;
    int val  ;
    int val2  ;
    int instruction ;
    int ret ;

public  :

    void  fetch( );

    VIRTUAL_INSTRUCTION * decode( ) ;

    inline void execute();

    void 	Push(int value);

    int   Pop();

    void RaiseException(int Exception ) const ;

    VIRTUAL_MACHINE(int * Base)
    {
        //---------- VirtualCPU initialization
        Processor                       = (VIRTUAL_CPU * )malloc(sizeof(VIRTUAL_CPU));
        this->Processor->BaseAddr       = reinterpret_cast<int *>(Base) ;
        this->Processor->ProgramCounter = reinterpret_cast<int *>(&PC)  ;
        this->Processor->Eflags         = 0 ;
        this->Processor->Regs           = (VIRTUAL_REGISTERS * )malloc(sizeof(VIRTUAL_REGISTERS) * sizeof(char) ) ;

        this->Processor->Regs->BP = 0 ;
        this->Processor->Regs->R1 = 0 ;
        this->Processor->Regs->R2 = 0 ;
        this->Processor->Regs->SP = 0 ;
        this->Processor->Regs->R3 = 0 ;
        this->Processor->Regs->R4 = 0 ;
        this->Processor->Regs->R5 = 0 ;
        this->Processor->Regs->R6 = 0 ;
        this->Processor->Regs->R7 = 0 ;
        this->Processor->Regs->R8 = 0 ;

        val         = 0 ;
        val2        = 0 ;
        instruction = 0 ;
        ret         = 0 ;


        //------------VIRTUAL_INSTRUCTION initialization
        Instruction                     = (VIRTUAL_INSTRUCTION * )malloc(sizeof(VIRTUAL_INSTRUCTION) );
        this->Instruction->OpCode       = 0 ;
        this->Instruction->Displacement = 0 ;
        this->Instruction->DestType     = 0 ;
        this->Instruction->SrcType      = 0 ;
        this->Instruction->ByteValue    = 0 ;
        this->Instruction->DstReg       = 0 ;
        this->Instruction->SrcReg       = 0 ;

        //-------VIRTUAL_STACK initialization
        this->Processor->VStack          = (VIRTUAL_STACK * )malloc(sizeof(VIRTUAL_STACK));
        this->Processor->VStack->item    = 0 ;
        this->Processor->VStack->IsEmpty = true ;
        this->Processor->VStack->Previous_Stack_Frame    = NULL ;
        this->Processor->Regs->SP        = NULL ;
        this->Processor->Regs->BP        = reinterpret_cast<VIRTUAL_STACK *>(this->Processor->VStack) ;

    };


    void show()
    {
        printf("\n EFLAGS : %x\n" ,this->Processor->EFLAGS );
    }


};

void VIRTUAL_MACHINE::RaiseException(int Exception )const
{
    Exception -= 1 ;

    const char  * const ErrorMessages[] = { "\nError : BYTE_OVERFLOW at address : %x \n",
                                            "\nError : INVALID_INSTRUCTION  at address : %x \n",
                                            "\nError : UNEXPECTED_LONG_JUMP at address : %x \n",
                                            "\nError : EMPTY_STACK at address : %x \n",
                                            "\nError : INVALID_RETURN_ADDRESS at address : %x \n"
                                          } ;

     fprintf(stderr,ErrorMessages[Exception],(Processor->BaseAddr  + *(Processor->ProgramCounter) ));
     system("pause");
     exit(-1);

}

void  VIRTUAL_MACHINE::fetch( )
{
    __TIMING_CHECK__ ;
    instruction = *(Processor->BaseAddr  + *(Processor->ProgramCounter) );


    if(instruction == HALT)
    {
        puts("\nProgram Exited Normally !");
        system("pause");
        exit(0) ;
    }

}

void  VIRTUAL_MACHINE::Push(int value)

{

    VIRTUAL_STACK  * temp =  (VIRTUAL_STACK * )malloc(sizeof(VIRTUAL_STACK));


    if( this->Processor->VStack->IsEmpty  == true )
    {
        __TIMING_CHECK__ ;

        this->Processor->VStack->item = value ;

        this->Processor->VStack->IsEmpty = false ;

    }
    else
    {

        temp->item = value ;
        temp->Previous_Stack_Frame = this->Processor->VStack ;
        this->Processor->VStack =  temp ;

        __TIMING_CHECK__ ;

        this->Processor->Regs->SP = this->Processor->VStack ;

    }

}

int VIRTUAL_MACHINE::Pop()
{

    this->Processor->VStack = this->Processor->Regs->SP ;

    if(this->Processor->VStack->IsEmpty == true )
    {

        RaiseException(EMPTY_STACK);
    }
    else
    {
        if( this->Processor->VStack->Previous_Stack_Frame == NULL )
        {
            __TIMING_CHECK__ ;

            val = this->Processor->VStack->item ;

            this->Processor->VStack->IsEmpty = true ;
            return val ;
        }
        else
        {

            val = this->Processor->VStack->item ;

            __TIMING_CHECK__ ;

            this->Processor->VStack   = this->Processor->VStack->Previous_Stack_Frame ;
            this->Processor->Regs->SP = this->Processor->VStack ;

            return val 	;
        }

    }


}

VIRTUAL_INSTRUCTION * VIRTUAL_MACHINE::decode(   )
{
    Instruction->OpCode        = (instruction & 0xF0000000) >> 28 ;
    Instruction->DestType      = (instruction & 0x0F000000) >> 24 ;
    Instruction->SrcType       = (instruction & 0x00F00000) >> 20 ;
    Instruction->Displacement  = (instruction & 0x00000F00) >> 8  ;
    Instruction->ByteValue     = (instruction & 0x000000FF)       ;
    Instruction->DstReg        = (instruction & 0x000F0000) >> 16 ;
    Instruction->SrcReg        = (instruction & 0x0000F000) >> 12 ;


    int NULl = 0 ;

    return (VIRTUAL_INSTRUCTION *)NULl ;
}

inline void VIRTUAL_MACHINE::execute()
{

    //Welcome to the wolrd of The  CPU
    switch(Instruction->OpCode)
    {

    case MOV :

        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE )
        {
            *((int *)Processor->Regs +  Instruction->DstReg - 1) =  Instruction->ByteValue ;

            __TIMING_CHECK__ ;

            printf("MOV R%d , %d \n", Instruction->DstReg - 1 , Instruction->ByteValue);
        }
        else if (Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG )
        {
            *((int *)Processor->Regs +  Instruction->DstReg - 1) = *((int *)Processor->Regs +  Instruction->SrcReg - 1) ;

            __TIMING_CHECK__ ;

            printf("MOV R%d , R%d \n", Instruction->DstReg - 1 , Instruction->SrcReg - 1);
        }
        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_DEREFERENCE)
        {
            *((int *)Processor->Regs +  Instruction->DstReg - 1) = (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->SrcReg - 1))) & 0x000000FF;

            __TIMING_CHECK__ ;

            printf("MOV R%d , [R%d] \n", Instruction->DstReg - 1 , Instruction->SrcReg - 1);
        }
        else if( Instruction->DestType == IS_DEREFERENCE && Instruction->SrcType == IS_REG)
        {

            val = (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->DstReg - 1))) ;
            val2 = *((int *)Processor->Regs +  Instruction->SrcReg - 1) ;

            __TIMING_CHECK__ ;
            (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->DstReg - 1))) =  (val & 0xFFFFFF00) | (val2 & 0x000000FF)  ;

            printf("MOV [R%d] , R%d \n", Instruction->DstReg - 1 , Instruction->SrcReg - 1);
        }
        else if(Instruction->DestType == IS_DEREFERENCE && Instruction->SrcType == IS_VALUE  )
        {
            val = (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->DstReg - 1))) ;

            val2 = Instruction->ByteValue ;

            __TIMING_CHECK__ ;
            *(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->DstReg - 1)) = (val & 0xFFFFFF00) | (val2 & 0x000000FF);

            printf("MOV R%d , %d \n", Instruction->DstReg - 1 ,Instruction->ByteValue );
        }

        break ;

    case ADD :
        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE  )
        {

            *((int *)Processor->Regs +  Instruction->DstReg -1) += Instruction->ByteValue;
            __TIMING_CHECK__ ;
            if (*((int *)Processor->Regs +  Instruction->DstReg -1) > 0xFF )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);
            }

            printf("ADD R%d , %d \n", Instruction->DstReg - 1 ,Instruction->ByteValue );

        }
        else if (Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {

            *((int *)Processor->Regs +  Instruction->DstReg -1) +=  *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;
            if (*((int *)Processor->Regs +  Instruction->DstReg -1) > 0xFF )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);
            }

            printf("ADD R%d , R%d \n", Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        else if (Instruction->DestType == IS_REG && Instruction->SrcType == IS_DEREFERENCE )
        {
            val = (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->SrcReg - 1)));
            *((int *)Processor->Regs +  Instruction->DstReg -1) += (val & 0x000000FF) ;

            __TIMING_CHECK__ ;
            if (*((int *)Processor->Regs +  Instruction->DstReg -1) > 0xFF )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);
            }

            printf("ADD R%d , [R%d] \n", Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        break ;
    case SUB :

        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE )
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) -= Instruction->ByteValue;
            __TIMING_CHECK__ ;
            if (*((int *)Processor->Regs +  Instruction->DstReg -1) < 0xFF  )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);
            }
            else if ( *((int *)Processor->Regs +  Instruction->DstReg -1) > -255 && *((int *)Processor->Regs +  Instruction->DstReg -1) < 0)
            {
                this->Processor->Eflags |= EFLAGS_MASK << (SIGN_FLAG * 4 ) ;
            }

            printf("SUB R%d , %d \n", Instruction->DstReg - 1 , Instruction->ByteValue );
        }

        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG )
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) -=  *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;
            if (*((int *)Processor->Regs +  Instruction->DstReg -1) < 0xFF  )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;

                RaiseException(BYTE_OVERFLOW);
            }
            else if ( *((int *)Processor->Regs +  Instruction->DstReg -1) > -255 && *((int *)Processor->Regs +  Instruction->DstReg -1) < 0)
            {
                this->Processor->Eflags |= EFLAGS_MASK << (SIGN_FLAG * 4 ) ;
            }

            printf("SUB R%d , R%d \n", Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        else if (Instruction->DestType == IS_REG && Instruction->SrcType == IS_DEREFERENCE )
        {
            val = (*(Processor->BaseAddr  + *((int *)Processor->Regs +  Instruction->SrcReg - 1)));

            __TIMING_CHECK__ ;
            *((int *)Processor->Regs +  Instruction->DstReg -1) -= (val & 0x000000FF) ;

            if (*((int *)Processor->Regs +  Instruction->DstReg -1) < 0xFF  )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);
            }
            else if ( *((int *)Processor->Regs +  Instruction->DstReg -1) > -255 && *((int *)Processor->Regs +  Instruction->DstReg -1) < 0)
            {
                this->Processor->Eflags |= EFLAGS_MASK << (SIGN_FLAG * 4 ) ;
            }

            printf("SUB R%d , [R%d] \n", Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        break ;
    case XOR :

        if( Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE )
        {
            __TIMING_CHECK__ ;
            *((int *)Processor->Regs +  Instruction->DstReg -1) ^= Instruction->ByteValue ;

            printf("XOR R%d , %d \n", Instruction->DstReg - 1 , Instruction->ByteValue );
        }
        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {

            *((int *)Processor->Regs +  Instruction->DstReg -1) ^= *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;

            printf("XOR R%d , R%d \n", Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        break ;

    case JMP :

        if(Instruction->SrcType == IS_REG )
        {

            val =  *((int *)Processor->Regs +  Instruction->SrcReg -1)	 ;

            __TIMING_CHECK__ ;
            PC = (int  ) val - 1  ;
            printf("JMP R%d \n",  Instruction->SrcReg -1 );
        }

        else if(Instruction->SrcType == IS_VALUE )
        {
            val = Instruction->ByteValue ;

            PC = (int ) val -1 ;

            printf("JMP %d \n",  Instruction->ByteValue );
        }
        break ;
    case MUL :
        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE )
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) *= Instruction->ByteValue ;
            __TIMING_CHECK__ ;
            if(*((int *)Processor->Regs +  Instruction->DstReg -1) > 0xFF)
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);

            }
            printf("MUL R%d , %d\n",  Instruction->DstReg - 1 , Instruction->ByteValue );
        }
        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) *= *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;
            if(*((int *)Processor->Regs +  Instruction->DstReg -1) > 0xFF)
            {
                this->Processor->Eflags |= EFLAGS_MASK << (OVERFLOW_FLAG * 4 ) ;
                RaiseException(BYTE_OVERFLOW);

            }

            printf("MUL R%d , R%d\n",  Instruction->DstReg - 1 , Instruction->SrcReg - 1 );

        }
        break ;
    case OR :

        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE  )

        {

            __TIMING_CHECK__ ;
            *((int *)Processor->Regs +  Instruction->DstReg -1) |= Instruction->ByteValue ;

            printf("OR R%d , %d\n",  Instruction->DstReg - 1 , Instruction->ByteValue );
        }

        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) |= *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;

            printf("OR R%d , R%d\n",  Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }

        break ;

    case AND :

        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE  )

        {
            __TIMING_CHECK__ ;
            *((int *)Processor->Regs +  Instruction->DstReg -1) &= Instruction->ByteValue ;

            printf("AND R%d , %d\n",  Instruction->DstReg - 1 , Instruction->SrcReg -1 );
        }
        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {
            *((int *)Processor->Regs +  Instruction->DstReg -1) &= *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            __TIMING_CHECK__ ;

            printf("AND R%d ,R%d\n",  Instruction->DstReg - 1 , Instruction->SrcReg - 1 );

        }

        break ;
    case CMP :

        if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_VALUE  )
        {

            val =  *((int *)Processor->Regs +  Instruction->DstReg -1) - Instruction->ByteValue ;

            if(val == 0 )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (ZERO_FLAG * 4 ) ;
                __TIMING_CHECK__ ;
            }
            if ( val < 0 )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (SIGN_FLAG * 4 ) ;
                __TIMING_CHECK__ ;
            }
            if (val > 0 )
            {
                this->Processor->Eflags &= 0x0FFF ;
                __TIMING_CHECK__ ;
            }

            printf("CMP R%d , %d\n",  Instruction->DstReg - 1 , Instruction->ByteValue );

        }
        else if(Instruction->DestType == IS_REG && Instruction->SrcType == IS_REG)
        {
            val =  *((int *)Processor->Regs +  Instruction->DstReg -1) - *((int *)Processor->Regs +  Instruction->SrcReg -1) ;

            if(val == 0 )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (ZERO_FLAG * 4 ) ;
                __TIMING_CHECK__ ;
            }

            else if ( val < 0 )
            {
                this->Processor->Eflags |= EFLAGS_MASK << (SIGN_FLAG * 4 ) ;
                __TIMING_CHECK__ ;
            }

            else if (val > 0 )
            {
                this->Processor->Eflags &= 0x0FFF ;
                __TIMING_CHECK__ ;
            }

            printf("CMP R%d , R%d\n",  Instruction->DstReg - 1 , Instruction->SrcReg - 1 );

        }

        break ;

    case PUSH :

        if(Instruction->SrcType == IS_REG )
        {
            val2 =  *((int *)Processor->Regs +  Instruction->SrcReg -1) ;
            __TIMING_CHECK__ ;
            Push(val2) ;
            printf("PUSH R%d \n",  Instruction->SrcReg - 1  );
        }

        else if(Instruction->SrcType == IS_VALUE)
        {

            val2 = Instruction->ByteValue ;
            __TIMING_CHECK__ ;
            Push(val2);
            printf("PUSH %d \n",  Instruction->ByteValue );

        }
        break ;

    case POP :

        if(Instruction->DestType == IS_REG )
        {

            val2 =  Pop();
            __TIMING_CHECK__ ;
            *((int *)Processor->Regs +  Instruction->DstReg -1) = val2 ;

            printf("POP R%d \n",  Instruction->DstReg - 1 );
        }

        break ;

    case JE :

        if((Processor->Eflags >> (ZERO_FLAG * 4 ) ) == 0x1)
        {
            if(Instruction->SrcType == IS_REG )
            {
                val = *((int *)Processor->Regs +  Instruction->SrcReg -1) ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;

                printf("JE R%d \n",  Instruction->SrcReg - 1 );

            }
            else if (Instruction->SrcType == IS_VALUE )
            {
                val = Instruction->ByteValue ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;
                printf("JE %d \n",  Instruction->ByteValue );
            }

        }
        break ;

    case JL :

        if((Processor->Eflags >> (SIGN_FLAG  * 4 ) ) == 0x1)
        {
            if(Instruction->SrcType == IS_REG )
            {
                val = *((int *)Processor->Regs +  Instruction->SrcReg -1) ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;
                printf("JL R%d \n",  Instruction->SrcReg - 1 );

            }
            else if (Instruction->SrcType == IS_VALUE )
            {
                val = Instruction->ByteValue ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;

                printf("JL %d \n",  Instruction->ByteValue );
            }

        }
        break ;

    case JA :

        if((Processor->Eflags >> (SIGN_FLAG * 4 ) ) == 0x0)
        {
            if(Instruction->SrcType == IS_REG )
            {
                val = *((int *)Processor->Regs +  Instruction->SrcReg -1) ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;
                printf("JA R%d \n",  Instruction->SrcReg - 1 );

            }
            else if (Instruction->SrcType == IS_VALUE )
            {
                val = Instruction->ByteValue ;
                __TIMING_CHECK__ ;
                PC = (int )val - 1 ;

                printf("JA %d \n",  Instruction->ByteValue );
            }

        }
        break ;

    case CALL :

        ret = PC + 1 ;
        if(Instruction->SrcType == IS_REG )
        {
            val = *((int *)Processor->Regs +  Instruction->SrcReg -1) ;
            __TIMING_CHECK__ ;
            PC = (int )val - 1 ;
            printf("CALL R%d \n",  Instruction->SrcReg - 1 );


        }

        else if(Instruction->SrcType == IS_VALUE )
        {
            val = Instruction->ByteValue ;
            __TIMING_CHECK__ ;
            PC = (int )val - 1 ;

            printf("JE %d \n",  Instruction->ByteValue );
        }
        break ;



    case RET :
        if(ret < 0 || ret > ( (sizeof(Processor->BaseAddr)) / 4 ))
        {

            RaiseException(INVALID_RETURN_ADDRESS);
        }
        __TIMING_CHECK__ ;
        PC = ret - 1 ;

    default :

        RaiseException(INVALID_INSTRUCTION);

        break ;
    }

}

#define STEALTH 0x00000004

typedef NTSTATUS (WINAPI *FNtCreateThreadEx)
(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
);

void RunCPU(VIRTUAL_MACHINE & VM)
{

    while(1)
    {
        VM.fetch();
        VM.decode();
        VM.execute();
        PC++;
    }
    system("pause");
}


int _tmain(int argc , _TCHAR * argv[])
{

    
	/*  0x11210007, 0x11121005, 0x11230001,
		0x11343000, 0x11250002, 0x13135000,
		0x13230008, 0x21250003, 0x21153000,
		0x21353000, 0x31250001, 0x31153000,
		0x31353000, 0x41250001, 0x41135000,
		0x81234005, 0x81154000, 0xA122300F,
		0xA1134000, 0x91210008, 0x91124000,
		0xD1240005, 0x50104000, 0x50200008,
		0x61010000 */

	puts("Flag :");
	char flag[50];
	memset(flag,'\0',50);
	fgets(flag, 50, stdin);
	/*Flag is L0PHTVM_D3T3C73D */
	int  Program[] = {                 0x11210000 | (flag[0] & 0x000000ff),
		                           0x11220000 | (flag[1] & 0x000000ff),
					   0x11230000 | (flag[2] & 0x000000ff),
					   0x11240000 | (flag[3] & 0x000000ff),
					   0x11250000 | (flag[4] & 0x000000ff),
					   0x11260000 | (flag[5] & 0x000000ff),
					   0x11270000 | (flag[6] & 0x000000ff),
					   0x11280000 | (flag[7] & 0x000000ff),
					   0x21210020/*ADD r1 , 0x20 */,
					   0x41210025/*XOR r1 , 0x25  //ins 10*/,
					   0xD1210049/*CMP R1 , 0x49*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x21220018/*ADD R2 , 0x18 */, 
					   0x41220045/*XOR R2 , 0x45*/,
					   0xD122000D/*CMP R2 , 0xD*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x31230005/*SUB R3 , 0x5*/,
					   0xD123004B/*CMP R3 , 0x45*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x21240002/*ADD R4 , 0x2*/,
					   0x81240002/*MUL R4 , 0x2*/, 
					   0xD1240094/*CMP R4 , 0x94*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x50105000/*PUSH R5*/,
					   0x50106000/*PUSH R6*/,
					   0x61090000/*POP R9*/,
					   0x11119000/*MOV R1 , R9*/,
					   0x11290003/*MOV R9 , 3*/,
					   0x31119000/*SUB R1 , R9*/,
					   0x81119000/*MUL R1 , R9*/,
					   0xD12100F9/*CMP R1 , 0xF9*/,
					   0xF0200067/*JNE 0x37 to HALT*/,//1F
					   0x61090000/*POP R9*/,
					   0x11129000/*MOV R2 , R9*/,
					   0x11290003/*MOV R9 , 3*/,
					   0x21290010/*ADD R9 , 0x10*/,
					   0x21129000/*ADD R2 , R9*/,
					   0xD1220067/*CMP R2 , 0x67*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x31270020/*SUB R7 , 0x20*/,
					   0xD127002D/*CMP R7 , 0x2D*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x2128003F/*ADD R8 , 0x3F*/,
					   0xD128009E/*CMP R7 , 0x2D*/,
					   0xF0200067/*JNE 0x37 to HALT*/,
					   0x11210000 | (flag[8]   & 0x000000ff),//2d
					   0x11220000 | (flag[9]   & 0x000000ff),
					   0x11230000 | (flag[0xA] & 0x000000ff),
					   0x11240000 | (flag[0xB] & 0x000000ff),
					   0x11250000 | (flag[0xC] & 0x000000ff),
					   0x11260000 | (flag[0xD] & 0x000000ff),
					   0x11270000 | (flag[0xE] & 0x000000ff),
					   0x11280000 | (flag[0xF] & 0x000000ff),
					   0x1129002C/*MOV R9 , 0x2C*/,//0x35
					   0x21290001/*ADD R9 , 0x1*/,
					   0x50109000/*PUSH R9*/,
					   0x50109000/*PUSH R9*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0x41290012/*XOR R9 , 0x12*/,
					   0x13199000/*MOV [R9] , R9*/,
					   0x61090000/*POP R9*/,
					   0xD1290035/*CMP R9 , 0x35*/,
					   0xD1290035/*CMP R9 , 0x35*/,
					   0xE0200067/*JE To HALT*/,
					   0xE0200067/*JE To HALT*/,
					   0x70200036/*JMP 0x35*/, 
					   0x1129002D/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290056/*CMP R9 , 0x56*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x1129002E/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290021/*CMP R9 , 0x33*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x1129002F/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290046/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290030/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290021/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290031/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290051/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290032/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290025/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290033/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290021/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290032/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD1290056/*CMP R9 , 0x44*/,
					   0xF0200067/*JNE 0x4F to HALT*/,
					   0x11290032/*MOV R9 , 0x2D*/,
					   0x11399000/*MOV R9 , [R9]*/,
					   0xD129003e/*CMP R9 , 0x44*/,

					   HALT
	 };
    VIRTUAL_MACHINE VM = VIRTUAL_MACHINE(Program);

    HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));

    FNtCreateThreadEx myNtCreateThreadEx = (FNtCreateThreadEx )GetProcAddress(ntdll,"NtCreateThreadEx");

    HANDLE CurrentThread ;

    myNtCreateThreadEx(&CurrentThread,(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff) ,0,GetCurrentProcess(),(LPTHREAD_START_ROUTINE)RunCPU,&VM,STEALTH,0,0,0,0);

    WaitForSingleObject(CurrentThread,INFINITE);

    system("pause");

    return 0;
}
