/*
 *  Created by Maryam Sepehri. 
 *  2017 Universita' degli Studi di Milano
 *
 *  ECC implementation of the protocol proposed in the paper "Efficient         
 *   Implementation of a Proxy-based Protocol for Data Sharing on the Cloud"
 *   To compile: gcc -o ECCPRO ECCPRO.c ec.c -lm -lgmp
 */

#include "elgamal.h"
#include "string.h"
#include "stdlib.h"

#define MAX_OWNERS 3  // define the number of data owners of the system
#define MAX_USERS 1   // define the number of authorized users of the system
#define PROXY_SIDE 3  // this number should be same as the MAX-OWNERS
#define CLOUD_SIDE 1   
#define DBSIZE 10

mpz_t *owners, *proxy, *cloud, *users, *yes, *no;
const int classify[]={4,3,3}; // the number of data that each data owner holds
//const int user_choose[]={2,3,2};
static FILE *fp, *fq, *fz, *fz1, *fz11, *fz12;

typedef unsigned long long timestamp_t;
static timestamp_t


//------------------------------------------------------------------------------------------------------------------------------
get_timestamp()
{
  struct timeval now;
  gettimeofday(&now,NULL);
  return now.tv_usec+(timestamp_t)now.tv_sec*1000000;
}

//------------------------------------------------------------------------------------------------------------------------------
void get_random_n_bits(mpz_t r, size_t bits)
{
  size_t size = (size_t) ceilf(bits/8);
  char *buffer = (char*) malloc(sizeof(char)*size);
  int prg = open("/dev/random", O_RDONLY);
  read(prg, buffer, size);
  close(prg);
  mpz_import (r, size, 1, sizeof(char), 0, 0, buffer);
  free(buffer);
}

//------------------------------------------------------------------------------------------------------------------------------

void get_random_n_prime(mpz_t r, mpz_t max) 
{
 do {
      get_random_n_bits(r, mpz_sizeinbase(max, 2));
      mpz_nextprime(r, r);
    } while (mpz_cmp(r, max) >= 0);
}

//------------------------------------------------------------------------------------------------------------------------------

void get_random_n(mpz_t r, mpz_t max) 
{
  do {
       get_random_n_bits(r, mpz_sizeinbase(max, 2));
     } while (mpz_cmp(r, max) >= 0);
}
//------------------------------------------------------------------------------------------------------------------------------

void Data_generation()
{
  int i,j,l,k,z,w;
  fp=fopen("str.txt","w+");
  if (fp==NULL)
   printf("OOPS! Unable to create file\n");
  for (i=0;i<MAX_OWNERS;i++)
   for (l=0;l<classify[i];l++)
    {
     j=GetRand(1,99);
     fprintf(fp,"%d\n",j);
    }

   fclose(fp);
}
//------------------------------------------------------------------------------------------------------------------------------
void key_generation(mpz_t master_key,mpz_t prime)
{
  int k,i;
  mpz_t randNum1, randNum2;
  mpz_init(randNum1);
  mpz_init(randNum2);
  
  for (k=0; k<MAX_OWNERS;k++)
   {
     get_random_n(randNum1, prime);
     while ((mpz_cmp(randNum1,master_key)>0)||(randNum1==0))
       get_random_n(randNum1, prime);
     mpz_set(owners[k],randNum1);
     mpz_sub(proxy[k],master_key,owners[k]);
     gmp_printf("the key of owner is: %Zd\n",owners[k]);
     gmp_printf("the key of proxy is: %Zd\n",proxy[k]);
    }
  for (i=0; i<MAX_USERS;i++)
   {
     get_random_n(randNum2, prime);
     mpz_set(users[i], randNum2);
     mpz_sub(cloud[i],master_key,users[i]);
     gmp_printf("the value of user key is: %Zd\n",users[i]);
   }
    
  mpz_clear(randNum1);
  mpz_clear(randNum2);

}
//------------------------------------------------------------------------------------------------------------------------------

int GetRand (int min, int max)
{
  static int Init=0;
  int rc;
  if (Init==0)
   {
     srand(time(NULL));
     Init=1;
    }
   rc= (rand()% (max-min+1)+min);
   return (rc);
 }

//------------------------------------------------------------------------------------------------------------------------------

void destroy_ciphertxt(ciphertext *ct) 
{
  if (ct)
  {
    mpz_clears(ct->c1, ct->c2, NULL);
    free(ct);
    ct = NULL;
   }
}



//------------------------------------------------------------------------------------------------------------------------------
/* setup elliptic curve, public and private key
 Using the brainpoolP160r1 - EC domain parameters
 http://www.ecc-brainpool.org/download/Domain-parameters.pdf
 */
void init_elgam_ec(elgam_ec_ctx **eec_ctx)
{
 *eec_ctx = (elgam_ec_ctx*) malloc(sizeof(elgam_ec_ctx));
 elliptic_curve *ecc = (elliptic_curve*)malloc(sizeof(elliptic_curve));
 (*eec_ctx)->ec = ecc;
 mpz_t tmp, tmp10;

 mpz_set_str(ecc->a, "340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16); 
 mpz_set_str(ecc->b, "1E589A8595423412134FAA2DBDEC95C8D8675E58", 16); 
 mpz_set_str(ecc->p, "E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16); 
 mpz_init((*eec_ctx)->priv_key);
 init_point(&(ecc->base));
 init_point(&((*eec_ctx)->pub_key));

 mpz_set_str(ecc->base->x, "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16); 
 mpz_set_str(ecc->base->y, "1667CB477A1A8EC338F94741669C976316DA6321", 16); 
 gmp_printf("\np = %Zd\n", ecc->p);
 get_random_n((*eec_ctx)->priv_key, ecc->p);
 gmp_printf("x = %Zd\n", (*eec_ctx)->priv_key);

 mpz_init_set(tmp, (*eec_ctx)->priv_key);
 mpz_init_set(tmp10,ecc->p);
 key_generation(tmp,tmp10);
 (*eec_ctx)->pub_key = ecc_scalar_mul((*eec_ctx)->ec, tmp, ecc->base);
 mpz_clears(tmp, NULL);
 gmp_printf("Base point P = (%Zd,%Zd)\n", ecc->base->x, ecc->base->y);
 gmp_printf("Public key xP =  (%Zd,%Zd)\n\n", ((*eec_ctx)->pub_key)->x, ((*eec_ctx)->pub_key)->y);
}


//------------------------------------------------------------------------------------------------------------------------------
cipherec* encrypt_ec(elgam_ec_ctx *eec)
{
  char line[255], val1[40], val2[40], val3[40],var5[200],var6[200], var3[800],var4[800], var15[800],var16[800];
  char *pos;
  int i,j,i1,j1,res;
  mpz_t const;
  unsigned long int count=1;
  mpz_t tmp3,rand11, tmp4, n1,n2,n11,n12,n3,n4;
  mpz_init(tmp3);
  mpz_init(tmp4);
  mpz_init(n1);
  mpz_init(n2);
  mpz_init(n3);
  mpz_init(n4);
  mpz_init(rand11);
  mpz_init(eec->eph_k);
  get_random_n(eec->eph_k, eec->ec->p);
  gmp_printf("\nEphemeral key = %Zd\n", eec->eph_k);
  cipherec *cipher = (cipherec*)malloc(sizeof(cipherec));
  init_point(&cipher->c1);
  init_point(&cipher->c2);
  init_point(&cipher->c3);
  init_point(&cipher->c4);
  init_point(&cipher->c5);
  init_point(&cipher->c7);
  init_point(&cipher->c6);
  init_point(&cipher->c9);
  init_point(&cipher->c11);
  init_point(&cipher->c12);

  fp=fopen("str.txt","r");
  if (fp==NULL)
   printf("\nFile does not exist, please check!\n");

   mpz_init_set(rand11,eec->eph_k);
   fq=fopen("ENCC1.txt","w+");
   if (fq==NULL)
     printf("\nFile does not exist for C1, please check!\n");

   fz=fopen("ENCC2.txt","w+");
   if (fz==NULL)
     printf("\nFile does not exist for C2, please check!\n");

   fz1=fopen("ENCC3.txt","w+");
   if (fz1==NULL)
     printf("\nFile does not exist for C22, please check!\n");

   rewind(fp);
   timestamp_t t0=get_timestamp();
   for (i=0;i<MAX_OWNERS;i++)
    for (j=0;j<classify[i];j++)
    {
      int jj=GetRand(1,99);
      mpz_add_ui(rand11,rand11,jj);
      cipher->c1=ecc_scalar_mul(eec->ec,rand11,eec->ec->base); // TO compute "r*p"
      mpz_mul(tmp3,eec->eph_k,owners[i]); //To Compute "r*key"
      cipher->c3=ecc_scalar_mul(eec->ec,tmp3,eec->ec->base);//To compute  "p*r*key_owner =Q*r"
     
      gmp_fscanf(fp,"%d\n", &res);
      mpz_init_set_d(tmp4,res);
      cipher->c4=ecc_scalar_mul(eec->ec,tmp4,eec->ec->base);//To compute "m1p"
      cipher->c2 = ecc_addition(eec->ec, cipher->c3, cipher->c4);
      gmp_fprintf(fz, "%Zd,%Zd,%Zd,%Zd\n",cipher->c1->x,cipher->c1->y,cipher->c2->x,cipher->c2->y);
     }

 timestamp_t t1=get_timestamp();
 double sec1=(t1-t0)/1000000.0L;
	
 rewind(fz);
	

 timestamp_t t2=get_timestamp();
		  
 for (i1=0;i1<MAX_OWNERS;i1++)
 for (j1=0;j1<classify[i1];j1++)
  {
   while (fgets(line,sizeof(line),fz)!=NULL)
   {
     if((pos=strchr(line,'\n'))!=NULL)
     {
       *pos='\0';
       strcpy(var3,strtok(line,","));// reading C1 from file ECC1
       mpz_set_str(n1, var3,10); 
       strcpy(var4,strtok(NULL,","));
       mpz_set_str(n2, var4,10);
       strcpy(var15,strtok(NULL,","));// reading C1 from file ECC1
       mpz_set_str(n3, var15,10); 
       strcpy(var16,strtok(NULL,","));
       mpz_set_str(n4, var16,10);
       mpz_init_set(cipher->c9->x,n1);
       mpz_init_set(cipher->c9->y,n2);
       mpz_init_set(cipher->c11->x,n3);
       mpz_init_set(cipher->c11->y,n4);
       cipher->c5=ecc_scalar_mul(eec->ec,cipher->c9,proxy[i1]);//c1*K'
       cipher->c12 = ecc_addition(eec->ec, cipher->c9, cipher->c11);
      }
    }
  }
	
 timestamp_t t3=get_timestamp();
 double sec2=(t3-t2)/1000000.0L;

 printf("*** The time needed for data encryption at owner sides is %f\n= ",sec1);
 printf("*** The time needed for data re-encryption at proxy side is %f\n= ",sec2);
 printf("*** The total time needed for key translation is %f\n= ",sec2+sec1);

 destroy_point(cipher->c1);
 destroy_point(cipher->c2);
 destroy_point(cipher->c3);
 destroy_point(cipher->c4);
 destroy_point(cipher->c5);
 destroy_point(cipher->c6);
 destroy_point(cipher->c7);
 destroy_point(cipher->c9);
 destroy_point(cipher->c11);
 destroy_point(cipher->c12);
 mpz_clear(tmp3);
 mpz_clear(rand11);
 mpz_clear(n1);
 mpz_clear(n2);
 mpz_clear(n3);
 mpz_clear(n4);
}

//------------------------------------------------------------------------------------------------------------------------------


int main() 
{
  owners= (mpz_t *) malloc(MAX_OWNERS*sizeof(mpz_t));
  proxy= (mpz_t *) malloc(PROXY_SIDE*sizeof(mpz_t));
  cloud= (mpz_t *)malloc(CLOUD_SIDE*sizeof(mpz_t));
  users=(mpz_t *) malloc(MAX_USERS*sizeof(mpz_t));
  elgam_ec_ctx *eec;
  init_elgam_ec(&eec);
  int i,j,k,c1,l;
  cipherec *c;
  
 Data_generation();
 c = encrypt_ec(eec); 
}




