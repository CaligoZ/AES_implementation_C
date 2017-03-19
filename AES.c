#include "stdio.h"


/*
 * Author: Vasudha Venkatesh, Gaurav Gupta
 * Purpose: Implementation of "AES Key – Encoded in the machine readable zone of a European ePassport" as Academic Project
 * Problem Statement Link: "https://www.mysterytwisterc3.org/en/challenges/level-ii/aes-key--encoded-in-the-machine-readable-zone-of-a-european-epassport"
 */

/*
 * Methods are implemented in the order they are represendted below.
 * References are written at the end.
 */

//implementation of Main method to intiate the call to encryption or decrytion
void encryption(); // main implementation of encryption.
__uint8_t ByteSub(__uint8_t num);// function implementing th logic for
void ShiftRow(__uint8_t fileData[][16], int rowNum); // implementation of Shift Row in Encryption
void MixColoumn(__uint8_t fileData[][16],int rowNum, int start); // implementation of Mix Coloumn in Encryption

void decryption(); // main implementation logic for AES Decryption
void inv_ShiftRow(__uint8_t data[][16], int rowNum); // function used to perform row shift in decryption
__uint8_t inv_ByteSub(__uint8_t num); // function used to perferom byte substitution during decryption
void inv_MixColumn(__uint8_t  fileData[][16],int rowNum, int start); // function used to perform Mix Column implementation in Decryption

__uint8_t galois_mul(__uint8_t a, __uint8_t b); // function used to implement galois multiplication.

static const __uint8_t sBox[256] =   {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const __uint8_t inv_sBox[256] = {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


int main(){
    int choice=-1;
    do{
        printf("\n Enter your choice:\n\t1. For Encryption.\n\t2. For Decryption\t");
        scanf("%d",&choice);
    }while(choice!=1&&choice!=2);
    if(choice==1){
        printf("\nYou entered choice for Encryption \n");
        encryption();
    }
    if(choice==2){
        printf("you entered choice for Decryption");
        decryption();
    }
}

void encryption(){
    FILE *inputFile,*outputFile;
    char inputFileName[200], outputFileName[200];
    printf("\nEnter the name of the file you would like to encrypt");
    scanf("%s",inputFileName);
    inputFile = fopen(inputFileName, "r");
    if(inputFile){
        printf("you entered %s", inputFileName);
        printf("\n Enter the name of the file that you would to store your Encrypted Data.");
        scanf("%s",outputFileName);
        outputFile = fopen(outputFileName,"w+");
        int totalCharInFile=0;
        fseek(inputFile, 0, SEEK_END);// seek the last character of the file;
        totalCharInFile = ftell(inputFile);//prvide the index of the last character which helps in determining the total number of character's present in a file
        fseek(inputFile, 0, SEEK_SET); //returns back to first character of the file
        char buff;
        int rows = (totalCharInFile/16)+1;
        __uint8_t fileData[rows][16];
        int rowNum=0,colNum=0;
        int counter=0;//a variable to calculate the number of colNum and later the num of rows

        // fetch whole data from the file and store it within the an array
        while((buff=fgetc(inputFile))!=EOF){
            ++counter;
            if(counter%16==0){
                rowNum+=1;
                colNum=0;
            }
            fileData[rowNum][colNum]=buff;
            colNum++;
        }

        //padded extra bits if the content does not have 16 bytes in the last blocks.
        if(colNum!=16){
            while(colNum!=16){
                fileData[rowNum][colNum] = 0;
                colNum++;
            }
        }

        rowNum=0;
        //code would start from here to encrypt 16 bytes once at a time
        while(rowNum!=rows){

            //add round key initially for every block
            /*for(int index=0; index<16; index++){
                fileData[rowNum][index]=fileData[rowNum][index]^keyData[index];
            }*/
            int KeyRounds = 10; //forExample
            //Number of rounds for one block; (last round is calculated seperately as it does not have mix coloumn layer
            for(int indexOfRounds=0; indexOfRounds<KeyRounds;indexOfRounds++){

                // Byte Substitution Start
                for(int index=0; index<16; index++){
                    fileData[rowNum][index]=ByteSub(fileData[counter][index]);
                }

                //Row Shift Start
                ShiftRow(fileData, rowNum);

                //mix coloumn(note not for the last round)
                if(indexOfRounds+1!=KeyRounds){
                    //mixColumn
                    for(int startIndex=0; startIndex<4; startIndex++){
                        MixColoumn(fileData, rowNum, startIndex*4);
                    }

                }
                //add round key
                /*for(int index=0; index<16; index++){
                    fileData[rowNum][index]=fileData[rowNum][index]^keyData[index];
                }*/

            }//end of number of rounds for one block

            //write the data of one round to the file
            for (int writeDataIndex = 0; writeDataIndex < 16; writeDataIndex++) {
                fputc(fileData[rowNum][writeDataIndex], outputFile);
            }

            //increment rowNum so that the process could be followed for the next round
            ++rowNum;
        }
        fclose(inputFile);
        fclose(outputFile);
    }
}
//****************************************************************
//************ Byte Substitution for Encryption ******************
//****************************************************************
__uint8_t ByteSub(__uint8_t num){
    return sBox[num];
}
//****************************************************************
//************ Shift Row for Encryption **************************
//****************************************************************
void ShiftRow(__uint8_t data[][16], int rowNum){
    __uint8_t temp[4][4]; // temp variable used to divide 16 bytes into 4X4 matrix and apply computation based on it
    //assign the data to one two dimensional array;
    for(int row=0; row<4; row++){
        for(int col=0; col<4; col++){
            temp[col][row]=data[rowNum][(4*row)+col];
        }
    }
    //row shift start
    int row=0;
    //first outer loop is for the number of rows
    for(int row=0; row<4; row++){
        //second outer loop determines how many times the shift would occur;
        for(int shifts=1; shifts<=row; shifts++){
            int count=0;
            __uint8_t temp1 = temp[row][0];
            // the while loop below is for shifting the three elements and the last one is shifted at the end;
            while(count<3){
                temp[row][count] = temp[row][count+1];
                count++;
            }
            temp[row][3] = temp1;
        }
    }

    for(int row=0; row<4; row++){
        for(int col=0; col<4; col++){
            data[rowNum][(row*4)+col] = temp[row][col];
        }
    }
}
//****************************************************************
//************ Mix Coloumn Implementation for Encryption *********
//****************************************************************
void MixColoumn(__uint8_t  fileData[][16],int rowNum, int start) {
    __uint8_t a[4];
    for(int index=0;index<4;index++) {
        a[index] = fileData[rowNum][start+index];
    }

    fileData[rowNum][start+0] = galois_mul(a[0],2) ^ galois_mul(a[3],1) ^ galois_mul(a[2],1) ^ galois_mul(a[1],3);
    fileData[rowNum][start+1] = galois_mul(a[1],2) ^ galois_mul(a[0],1) ^ galois_mul(a[3],1) ^ galois_mul(a[2],3);
    fileData[rowNum][start+2] = galois_mul(a[2],2) ^ galois_mul(a[1],1) ^ galois_mul(a[0],1) ^ galois_mul(a[3],3);
    fileData[rowNum][start+3] = galois_mul(a[3],2) ^ galois_mul(a[2],1) ^ galois_mul(a[1],1) ^ galois_mul(a[0],3);

}
void decryption(){
    FILE *inputFile,*outputFile;
    char inputFileName[200], outputFileName[200];
    printf("\nEnter the name of the file that is encrypted");
    scanf("%s",inputFileName);
    inputFile = fopen(inputFileName, "r");
    if(inputFile){
        printf("you entered %s", inputFileName);
        printf("\n Enter the name of the file to store your plain text data.");
        scanf("%s",outputFileName);
        outputFile = fopen(outputFileName,"w+");
        int totalCharInFile=0;
        fseek(inputFile, 0, SEEK_END);// seek the last character of the file;
        totalCharInFile = ftell(inputFile);//prvide the index of the last character which helps in determining the total number of character's present in a file
        fseek(inputFile, 0, SEEK_SET); //returns back to first character of the file
        char buff;
        int rows = (totalCharInFile/16)+1;
        __uint8_t fileData[rows][16];
        int rowNum=0,colNum=0;
        int counter=0;//a variable to calculate the number of colNum and later the num of rows

        // fetch whole data from the file and store it within the an array
        while((buff=fgetc(inputFile))!=EOF){
            ++counter;
            if(counter%16==0){
                rowNum+=1;
                colNum=0;
            }
            fileData[rowNum][colNum]=buff;
            colNum++;
        }

        rowNum=0;
        //code would start from here to encrypt 16 bytes once at a time
        while(rowNum!=rows){
            //add round key initially for every block
            /*for(int index=0; index<16; index++){
                fileData[rowNum][index]=fileData[rowNum][index]^keyData[index];
            }*/
            int KeyRounds = 10; // for example.
            //Number of rounds for one block; (last round is calculated seperately as it does not have mix coloumn layer
            for(int indexOfRounds=KeyRounds-1; indexOfRounds>=0;indexOfRounds--){

                //Row Shift Start
                inv_ShiftRow(fileData, rowNum);


                // Byte Substitution Start for decryption
                for(int index=0; index<16; index++){
                    fileData[rowNum][index]=inv_ByteSub(fileData[counter][index]);
                }


                //add round key
                /*for(int index=0; index<16; index++){
                    fileData[rowNum][index]=fileData[rowNum][index]^keyData[index];
                }*/


                //mix coloumn(note not included for the last round)
                if(indexOfRounds==0){
                    //mixColumn
                    for(int startIndex=0; startIndex<4; startIndex++){
                        inv_MixColumn(fileData, rowNum, startIndex*4);
                    }

                }

            }//end of number of rounds for one block

            //write the data of one round to the file
            for (int writeDataIndex = 0; writeDataIndex < 16; writeDataIndex++) {
                fputc(fileData[rowNum][writeDataIndex], outputFile);
            }

            //increment rowNum so that the process could be followed for the next round
            ++rowNum;
        }
        fclose(inputFile);
        fclose(outputFile);
    }
}

//****************************************************************
//************ Shift Row for Decryption **************************
//****************************************************************
void inv_ShiftRow(__uint8_t data[][16], int rowNum){
    __uint8_t temp[4][4]; // temp variable used to divide 16 bytes into 4X4 matrix and apply computation based on it
    //assign the data to one two dimensional array;
    for(int row=0; row<4; row++){
        for(int col=0; col<4; col++){
            temp[col][row]=data[rowNum][(4*row)+col];
        }
    }
    //row shift start
    int row=0;
    //first outer loop is for the number of rows
    for(int row=0; row<4; row++){
        //second outer loop determines how many times the shift would occur;
        for(int shifts=1; shifts<=row; shifts++){
            int count=3;
            __uint8_t temp1 = temp[row][3];
            // the while loop below is for shifting the three elements and the last one is shifted at the end;
            while(count>0){
                temp[row][count] = temp[row][count-1];
                --count;
            }
            temp[row][0] = temp1;
        }
    }

    for(int row=0; row<4; row++){
        for(int col=0; col<4; col++){
            data[rowNum][(row*4)+col] = temp[row][col];
        }
    }
}
//****************************************************************
//************ Byte Substitution for Decryption ******************
//****************************************************************
__uint8_t inv_ByteSub(__uint8_t num){
    return inv_sBox[num];
}
//****************************************************************
//************ Mix Coloumn Implementation for Decryption *********
//****************************************************************
void inv_MixColumn(__uint8_t  fileData[][16],int rowNum, int start) {
    __uint8_t a[4];
    for(int index=0;index<4;index++) {
        a[index] = fileData[rowNum][start+index];
    }
    fileData[rowNum][start+0] = galois_mul(a[0],14) ^ galois_mul(a[3],9) ^ galois_mul(a[2],13) ^ galois_mul(a[1],11);
    fileData[rowNum][start+1] = galois_mul(a[1],14) ^ galois_mul(a[0],9) ^ galois_mul(a[3],13) ^ galois_mul(a[2],11);
    fileData[rowNum][start+2] = galois_mul(a[2],14) ^ galois_mul(a[1],9) ^ galois_mul(a[0],13) ^ galois_mul(a[3],11);
    fileData[rowNum][start+3] = galois_mul(a[3],14) ^ galois_mul(a[2],9) ^ galois_mul(a[1],13) ^ galois_mul(a[0],11);

}
//****************************************************************
//************ Galois Multiplication used in Mix Columns *********
//****************************************************************

__uint8_t galois_mul(__uint8_t a, __uint8_t b) {
    __uint8_t p = 0;
    __uint8_t counter;
    __uint8_t hi_bit_set;
    for(counter = 0; counter < 8; counter++) {
        if((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if(hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/*
 ************************ Refereces **************************
 * mix coloumn in encryption and inverse mix coloumn in decryption is referenced from http://www.samiam.org/mix-column.html
 * galois multiplication method is referenced from http://www.samiam.org/galois.html
 */