#include <stdio.h>
#include <string.h>

#define MAX_BUF  256
#define IV 0b11001011

void encode(unsigned char*, unsigned char*, unsigned char);
void decode(unsigned char*, unsigned char*, unsigned char, int);
unsigned char computeKey(unsigned char);
unsigned char encryptByte(unsigned char, unsigned char);
unsigned char decryptByte(unsigned char, unsigned char);

unsigned char getBit(unsigned char, int);
unsigned char setBit(unsigned char, int);
unsigned char clearBit(unsigned char, int);


unsigned char xor (unsigned char , unsigned char , int );
unsigned char circularLeftShift(unsigned char src);
unsigned char circularRightShift(unsigned char src);
unsigned char getPartialKey(char*);
void printFinal(unsigned char* , unsigned char* , int );






int main()
{
  char str[8];
  int choice;

  unsigned char k;
  unsigned char pt[MAX_BUF];
  unsigned char ct[MAX_BUF];
  unsigned char partialKey;
  int numBytes =0;



  do{
    printf("\nYou may:\n");
    printf("  (1) Encrypt a message \n");
    printf("  (2) Decrypt a message \n");
    printf("  (0) Exit \n");
    printf("\n  what is your selection: ");

    fgets(str, sizeof(str), stdin);
    sscanf(str, "%d", &choice);

    switch (choice) {

      case 0://Exit
        return(0);

      case 1://Encryption
        //get partial key from user
        partialKey = getPartialKey(str);

        //convert partial key to actual key
        k = computeKey(partialKey);

        //get plaintext from user
        printf("\nEnter plaintext: \n" );
        fgets(pt, sizeof(pt), stdin);


        encode(pt, ct, k);
        break;

      case 2://Decryption
        partialKey = getPartialKey(str);

        k = computeKey(partialKey);

        //get cyphertext from user
        printf("\nEnter cyphertext: \n" );
        unsigned int userCypher;
        int size = 0;
        scanf("%u",&userCypher);
        while(userCypher != -1){
            ct[size++] = userCypher;
            scanf("%u",&userCypher);
            numBytes++;
        }

        decode(ct, pt, k, numBytes);
        break;

      default:
        printf("Error. Must enter either '1' or '2'\n" );
        break;
    }
  }
  while(choice < 1 || choice > 2);

  return (0);

}//closes main


/*
  Function:  getBit
  Purpose:   retrieve value of bit at specified position
       in:   character from which a bit will be returned
       in:   position of bit to be returned
   return:   value of bit n in character c (0 or 1)
*/
unsigned char getBit(unsigned char c, int n)
{
  return ((c & (1 << n)) >> n);
}

/*
  Function:  setBit
  Purpose:   set specified bit to 1
       in:   character in which a bit will be set to 1
       in:   position of bit to be set to 1
   return:   new value of character c with bit n set to 1
*/
unsigned char setBit(unsigned char c, int n)
{
  c = (c | (1 << n));
  return c;
}

/*
  Function:  clearBit
  Purpose:   set specified bit to 0
       in:   character in which a bit will be set to 0
       in:   position of bit to be set to 0
   return:   new value of character c with bit n set to 0
*/
unsigned char clearBit(unsigned char c, int n)
{
  c = (c & (~(1 << n)));
   return c;
}

/*
  Function:  encode
  Purpose:   encrypts the plaintext string, one byte at a time, using the key;
             and it stores each resulting cyphertext byte in the ct array

       in:   plaintext array corresponding to the plaintext entered by the user
       in:   array in which the encoded plaintext will be stored
       out:   cypher key

*/
void encode(unsigned char* pt, unsigned char* ct, unsigned char k){
  unsigned char sourceByte;
  unsigned char finishedByte;

    for(int i =0; i<(strlen(pt)); i++){
      //xor
      sourceByte = xor(pt[i],finishedByte, i);

      //xor and shift
      finishedByte = encryptByte(sourceByte, k);
      ct[i] = finishedByte;
    }

    printFinal(pt,ct,1);

}

/*
  Function:   decode
  Purpose:    decrypts the cyphertext one byte at a time, using the key;
              and it stores each resulting plaintext byte in the pt array

       in:   array of unsigned char representing the cyphertext
       in:   array in which the decoded cyphertext will be stored
       out:   cypher key
       out:   number of bytes in cypher
*/
void decode(unsigned char *ct, unsigned char *pt, unsigned char k, int numBytes){
  //same varibales names were used as encode function for clarity
  unsigned char sourceByte;
  unsigned char finishedByte;
  unsigned char letterByte;

  for(int i=0; i<(numBytes); i++){


    finishedByte=ct[i];
    //circular shift and keyxor
    sourceByte = decryptByte(finishedByte,k);

    //xor
    letterByte=xor(sourceByte,ct[i-1],i);

    pt[i] = letterByte;

  }

  printFinal(pt,ct,2);


}


/*
  Function:  xor;
  Purpose:   performs xor between 2 bytes
       in:   first byte to be xored
       in:   second byte to be xored
       out:   first iteration checker
*/
unsigned char xor (unsigned char first, unsigned char second, int selection){
  unsigned char xoredByte;

  if(selection==0){
    return xoredByte = first^IV;
  }else{
    return xoredByte = first^second;
  }

}

/*
  Function:  computeKey
  Purpose:   computes the key from this partial key
       in:   partial key entered by the user
   return:   computed key
*/
unsigned char computeKey(unsigned char partial){
  int mirrorPos;
  unsigned char f;
  //for least significant values
  for(int i=0; i<=3;i++){
    f=getBit(partial,i);
    mirrorPos=(7-i);
    //setting current bit value to mirrorPos bit value
    if(f==0){
      partial=clearBit(partial,mirrorPos);
    }else{
      partial=setBit(partial,mirrorPos);
    }

  }

  return partial;

}

/*
  Function:  encryptByte
  Purpose:   encrypts the source byte using the key
       in:   single source byte to be encrypted
       in:   key which will be used to encrypt source byte
   return:   encrypted source byte
*/
unsigned char encryptByte(unsigned char src, unsigned char k){

  //perform circular left shift by 2
  unsigned char tempSrc=circularLeftShift(src);

  unsigned char ctByte = 0;
  unsigned char srcBit;
  unsigned char keyBit;
  unsigned char xored;

  //get current bit and mirror postion bit and then xor them and then set cipherbyte values based on the xor
  for(int i=0; i<=7;i++){
    int mirrorPos=(7-i);

    srcBit=getBit(tempSrc,i);


    keyBit=getBit(k,mirrorPos);

    xored = xor(srcBit,keyBit,1);

      if(xored==1){
        ctByte=setBit(ctByte,i);

      }

  }

  return ctByte;

}

/*
  Function:  decryptByte
  Purpose:   decrypts byte using given key
       in:   single source byte to be decrypted
       in:   key which will be used to decrypt source byte
   return:   decrypted source byte
*/
unsigned char decryptByte(unsigned char ct, unsigned char k){


  unsigned char ctBit;
  unsigned char keyBit;
  unsigned char xored;
  unsigned char src;
  unsigned char tempByte = 0;

  //get current bit and mirror postion bit and then xor them and then set cipherbyte values based on the xor
  for(int i=0; i<=7;i++){
    int mirrorPos=(7-i);

    ctBit=getBit(ct,i);


    keyBit=getBit(k,mirrorPos);



    xored = xor(ctBit,keyBit,1);
      if(xored==1){
        tempByte=setBit(tempByte,i);

      }
  }

  //perfrom cicrular right shift by 2
  src = circularRightShift(tempByte);

  return src;



}



/*
  Function:  circularLeftShift
  Purpose:   performs circular left shift by 2 on given byte
       in:   source byte to be shifted
   return:   shifted source byte
*/
unsigned char circularLeftShift(unsigned char src){
  //save eight and seventh position bits
  unsigned char eighthPos = getBit(src,7);
  unsigned char seventhPos = getBit(src, 6);
  unsigned char tempSrc =0;

  //shift bits left by 2
  for (int i = 0; i < 7; i++) {
    if(getBit(src,i) == 0){
        tempSrc=clearBit(tempSrc,i+2);
    }else{
        tempSrc=setBit(tempSrc,i+2);
    }
  }

  //set first and second position bits to the bits that were saved previously
  if(eighthPos==0){
    tempSrc = clearBit(tempSrc,1);
  }else{
    tempSrc = setBit(tempSrc,1);
  }

  if(seventhPos==0){
    tempSrc = clearBit(tempSrc,0);
  }else{
    tempSrc = setBit(tempSrc,0);
  }

  return tempSrc;
}


/*
  Function:  circularRightShift
  Purpose:   performs circular right shift by 2 on given byte
       in:   source byte to be shifted
   return:   shifted source byte
*/
unsigned char circularRightShift(unsigned char src){

  //save first and second position bits
  unsigned char firstPos = getBit(src,0);
  unsigned char secondPos = getBit(src, 1);
  unsigned char tempSrc =0;

  //shift bits right by 2
  for (int i = 7; i >= 2; i--) {
    if(getBit(src,i) == 0){
        tempSrc=clearBit(tempSrc,i-2);
    }else{
        tempSrc=setBit(tempSrc,i-2);
    }
  }

  //set seventh and eighth position bits to the bits that were saved previously
  if(firstPos==0){
    tempSrc = clearBit(tempSrc,6);
  }else{
    tempSrc = setBit(tempSrc,6);
  }

  if(secondPos==0){
    tempSrc = clearBit(tempSrc,7);
  }else{
    tempSrc = setBit(tempSrc,7);
  }

  return tempSrc;
}

/*
  Function:  getPartialKey
  Purpose:   ask for userInput and does error checking to get the partial key
       in:   variable to store userinput
   return:   partial key entered by user
*/
unsigned char getPartialKey(char* str){
  unsigned char partialKey=0;
  while(1){
    printf("Enter the partial key (between 1 and 15): " );
    fgets(str, sizeof(str), stdin);
    sscanf(str, "%hhu", &partialKey);
    if(partialKey>=1 && partialKey<=15){
      break;
    }
  }
  return partialKey;
}



/*
  Function:  printFinal;
  Purpose:   prints plain text or cyphertext
       in:   plaintext/cyphertext array to be printed
       in:   selection to choose whether plaintext is printed or cyphertext
*/
void printFinal(unsigned char* pt, unsigned char* ct, int selection){
  int length = strlen(pt);
  if(selection ==1){
    printf("\nCyphertext: \n" );
    for(int i=0; i<length; i++){
      printf("%03d ", ct[i]);
    }
    printf("\n" );

  }else{
    printf("\nPlaintext: \n" );
    for(int i=0; i<length; i++){
      printf("%c", pt[i]);
    }
  }
}
