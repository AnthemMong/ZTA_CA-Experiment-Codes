//2020-10-03
//compile: gcc akeiov.c -lmiracl -o akeiov

# include<stdio.h>
# include<stdlib.h>
# include<string.h>
# include<time.h>
# include<sys/time.h>
# include<miracl/miracl.h>

# define BIGLENG 128
# define IDLEN 128

# define HASH_LEN 20
# define MAXLEN 1024

void hash(unsigned char* str, int len, unsigned char* result);
void h1(big id, epoint* Xi, epoint* Pi, unsigned char* result);
// void h2(big ida, big idg, epoint* Sa, epoint* Sg, epoint* Ca, epoint* Cg, epoint* Ta1, epoint* Ta2, epoint* Tg1, epoint* Tg2,  epoint* K1, epoint* K2, unsigned char* result);
void h2(epoint* K1, unsigned char* result);
void h3(big ida, big idg, epoint* K1, unsigned char* result);
void h4(big ida, big idg, epoint* Sa, epoint* Sg, epoint* K1, epoint* K2, unsigned char* result);
int get_biglen(big b);
int get_pointlen(epoint* e);
void print_point(epoint* e);
void bigmod(big* b, big* modular);
void hashbytes_to_big(int len, unsigned char* hashbytes, big* result);
void lrandom(big seed, int biglen, unsigned char* randstr);
void strxor2(int len, unsigned char* str1, unsigned char* str2, unsigned char* xorresult);
void strxor3(int len, unsigned char* str1, unsigned char* str2, unsigned char* str3, unsigned char* xorresult);
void urandom(int biglen, unsigned char* randstr);
void HAMC(int len, big tk, big id, unsigned char* ra1, unsigned char* CMa, unsigned char* result);


// Use elliptic curve of the form y^2=x^3+Ax+B
// parameter p, p is a prime
char *ecp ="FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF";

// parameter A
char *eca ="D6031998D1B3BBFEBF59CC9BBFF9AEE1";

// parameter B
char *ecb="5EEEFCA380D02919DC2C6558BB6D8A5D";

// elliptic curve - point of prime order (x,y) 
char *ecx="7B6AA5D85E572983E6FB32A7CDEBC140";
char *ecy="27B6916A894D3AEE7106FE805FC34B44";

// group oder q
char *ecq="3FFFFFFF7FFFFFFFBE0024720613B5A3";

int main(int argc, char* argv[])
{
    time_t seed;
    struct timeval start, end, start1, end1, start2, end2;
    int sumlen;
    epoint* P, *Ppub, *Ptemp1, *Ptemp2, *Ptemp3, *Sa, *Sg, *Ca, *Cg, *Ea, *Eg, *Ta1, *Ta2, *Tg1, *Tg2, *Ka1, *Kg1, *Ka2, *Kg2;
    big IDa, IDg, sa, sg, s, ca, rg, ha, hg, Aa1, Ag1, Ag1p, Aa1p, Aa2, Ag2, seeda, seedg, Aa3, Ag3, pa, pb, ea, eg, big_ka1, big_kg1, big_ka2, big_kg2, temp1, temp2, SKab, SKba;
    big tka, tkg;
    big eparam_a, eparam_b, eparam_p, eparam_x, eparam_y, eparam_q;
    miracl *mip;

    unsigned char hash_result[HASH_LEN];
    
    
#ifndef MR_NOFULLWIDTH   
    mip=mirsys(20,0);
#else
    mip=mirsys(20,MAXBASE);
#endif
    sa = mirvar(0);
    sg = mirvar(0);
    s = mirvar(0);
    ca = mirvar(0);
    rg = mirvar(0);
    ha = mirvar(0);
    hg = mirvar(0);
    Aa1 = mirvar(0);
    Ag1 = mirvar(0);
    Ag1p = mirvar(0);
    Aa1p = mirvar(0);
    Aa2 = mirvar(0);
    Ag2 = mirvar(0);
    seeda = mirvar(0);
    seedg = mirvar(0);
    tka = mirvar(0);
    tkg = mirvar(0);
    Aa3 = mirvar(0);
    Ag3 = mirvar(0);
    pa = mirvar(0);
    pb = mirvar(0);
    ea = mirvar(0);
    eg = mirvar(0);

    big_ka1 = mirvar(0);
    big_kg1 = mirvar(0);
    big_ka2 = mirvar(0);
    big_kg2 = mirvar(0);

    temp1 = mirvar(0);
    temp2 = mirvar(0);

    IDa = mirvar(0);
    IDg = mirvar(0);
    SKab = mirvar(0);
    SKba = mirvar(0);

    eparam_a = mirvar(0);
    eparam_b = mirvar(0);
    eparam_p = mirvar(0);
    eparam_q = mirvar(0);
    eparam_x = mirvar(0);
    eparam_y = mirvar(0);

    time(&seed);
    irand((unsigned long)seed);

    printf("PKG Init Phase......\n");
    gettimeofday(&start, NULL);  
    
    //convert(-3, eparam_a);
    mip->IOBASE=16;
    cinstr(eparam_a, eca);
    cinstr(eparam_b, ecb);
    cinstr(eparam_p, ecp);
    cinstr(eparam_q, ecq);      
    ecurve_init(eparam_a, eparam_b, eparam_p, MR_BEST);  /* Use PROJECTIVE if possible, else AFFINE coordinates */

    P = epoint_init();
    cinstr(eparam_x, ecx);
    cinstr(eparam_y, ecy);
    //mip->IOBASE=10;
    epoint_set(eparam_x, eparam_y, 0, P);

    bigbits(BIGLENG, s);
    Ppub = epoint_init();
    ecurve_mult(s, P, Ppub);

    gettimeofday(&end, NULL);
    printf("PKG init time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("Private Key Extraction Phase......\n");
    gettimeofday(&start, NULL);
    //printf("Device Produces Partial Private Key......\n");

    // int i;
    // for (i = 0; i < 100; i++)
    // {
        bigbits(BIGLENG, sa);
        bigbits(IDLEN, IDa);
        Sa = epoint_init();
        ecurve_mult(sa, P, Sa);
    
        //printf("Gateway Produces Partial Private Key......\n");

        bigbits(BIGLENG, sg);
        bigbits(IDLEN, IDg);
        Sg = epoint_init();
        ecurve_mult(sg, P, Sg);

        //printf("PKG Produces Partial Private Key......\n");

        bigbits(BIGLENG, ca);
        bigbits(BIGLENG, rg);
        Ca = epoint_init();
        Cg = epoint_init();

        ecurve_mult(ca, P, Ca);
        ecurve_mult(rg, P, Cg);

        h1(IDa, Sa, Ca, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &ha);
        // copy(ha, Aa1);
        h1(IDg, Sg, Cg, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &hg);
        // copy(hg, Ag1);

        multiply(ha, s, ha);
        add(ca, ha, pa);
        bigmod(&pa, &eparam_q);

        multiply(hg, s, hg);
        add(rg, hg, pb);
        bigmod(&pb, &eparam_q);

    //}
   

    gettimeofday(&end, NULL);
    printf("private key extraction time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("Key Agreement Phase......\n");
    gettimeofday(&start, NULL);
    //printf("Device Computes Ephemeral Key......\n");

    bigbits(BIGLENG, ea);
    Ea = epoint_init();
    Ta1 = epoint_init();
    Ta2 = epoint_init();

    ecurve_mult(ea, P, Ea);
    ecurve_mult(pa, Ea, Ta1);
    ecurve_mult(sa, Ea, Ta2);

    h1(IDa, Sa, Ca, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Aa1);
   

    //printf("Device sends Aa1\n");
    h1(IDa, Sa, Ca, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Aa1p);
    if (compare(Aa1, Aa1p) == 0)
        printf("A1 YES\n");

    bigbits(BIGLENG, eg);
    Eg = epoint_init();
    Tg1 = epoint_init();
    Tg2 = epoint_init();
 
    ecurve_mult(eg, P, Eg);
    ecurve_mult(pb, Eg, Tg1);
    ecurve_mult(sg, Eg, Tg2);

    h1(IDg, Sg, Cg, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Ag1);
    
    
    //printf("Gateway sends Ag1\n");
    h1(IDg, Sg, Cg, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Ag1p);
    if (compare(Ag1, Ag1p) == 0)
        printf("A1 YES\n");

    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();

    ecurve_mult(Ag1p, Ppub, Ptemp1);
    ecurve_add(Cg, Ptemp1);
    multiply(ea, pa, temp1);
    bigmod(&temp1, &eparam_q);

  
    Ka1 = epoint_init();
    ecurve_mult(temp1, Ptemp1, Ka1);
    ecurve_mult(pa, Tg1, Ptemp2);
    ecurve_add(Ptemp2, Ka1);
    
    h3(IDa, IDg, Ka1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Aa2);

    h2(Ka1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &seeda);
    // printf("seeda: ");
    // cotnum(seeda, stdout);
    // Ka2 = epoint_init();
    // multiply(sa, ea, temp1);
    // bigmod(&temp1, &eparam_q);
    // ecurve_mult(temp1, Tg2, Ka2);
    

    //printf("Device sends Aa2\n");
    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();
    
    ecurve_mult(Aa1p, Ppub, Ptemp1);
    ecurve_add(Ca, Ptemp1);
    multiply(eg, pb, temp1);
    bigmod(&temp1, &eparam_q);
    Kg1 = epoint_init();
    ecurve_mult(temp1, Ptemp1, Kg1);

    ecurve_mult(pb, Ta1, Ptemp2);
    ecurve_add(Ptemp2, Kg1);

    h2(Ka1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &seedg);
    // printf("seedg: ");
    // cotnum(seedg, stdout);

    h3(IDa, IDg, Kg1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Ag2);
    if (compare(Aa2, Ag2) == 0)
        printf("A2 YES\n");
    
    Kg2 = epoint_init();
    multiply(sg, eg, temp1);
    bigmod(&temp1, &eparam_q);
    ecurve_mult(temp1, Ta2, Kg2);

    h2(Kg2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &tkg);
    // printf("tkg: ");
    // cotnum(tkg, stdout);

    h4(IDa, IDg, Sa, Sg, Kg1, Kg2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Ag3);

    //printf("Device sends Ag3\n");
    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();

    Ka2 = epoint_init();
    multiply(sa, ea, temp1);
    bigmod(&temp1, &eparam_q);
    ecurve_mult(temp1, Tg2, Ka2);

    h2(Ka2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &tka);
    // printf("tka: ");
    // cotnum(tka, stdout);

    h4(IDa, IDg, Sa, Sg, Ka1, Ka2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &Aa3);
    if (compare(Aa3, Ag3) == 0)
        printf("A3 YES\n");


    gettimeofday(&end, NULL);
    printf("Initial Authentication Time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("Continuous Authentication\n");
    gettimeofday(&start, NULL);
    //printf("Device sends CAa");
    unsigned char randstra1[HASH_LEN];
    unsigned char randstra2[HASH_LEN];
    unsigned char xortemp[HASH_LEN];
    unsigned char idastr[HASH_LEN];
    unsigned char tkastr[HASH_LEN];
    unsigned char CMa[HASH_LEN];
    unsigned char CAa[HASH_LEN];


    lrandom(seeda, BIGLENG/8, randstra1);
    urandom(BIGLENG/8, randstra2);
    // hashbytes_to_big(HASH_LEN, randstra2, &temp1);
    // printf("ra2: ");
    // cotnum(temp1, stdout);

    
    cotstr(IDa, idastr);
    cotstr(tka, tkastr);
    strxor3(HASH_LEN, idastr, randstra1, tkastr, xortemp);

    hash(xortemp, strlen(xortemp), hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &temp1);
    // printf("h: ");
    // cotnum(temp1, stdout);

    strxor2(HASH_LEN, randstra2, hash_result, CMa);
    hashbytes_to_big(HASH_LEN, CMa, &temp1);
    // printf("CMa: ");
    // cotnum(temp1, stdout);

    HAMC(HASH_LEN, tka, IDa, randstra1, CMa, CAa);
    // hashbytes_to_big(HASH_LEN, CAa, &temp1);
    // cotnum(temp1, stdout);

    //printf("Gateway sends CAa");
    unsigned char randstrg1[HASH_LEN];
    unsigned char randstrg2[HASH_LEN];
    unsigned char ra2p[HASH_LEN];
    //unsigned char xortemp[HASH_LEN];
    unsigned char idgstr[HASH_LEN];
    unsigned char tkgstr[HASH_LEN];
    unsigned char CMg[HASH_LEN];
    unsigned char CAg[HASH_LEN];
    unsigned char CAap[HASH_LEN];


    lrandom(seeda, BIGLENG/8, randstrg1);
    urandom(BIGLENG/8, randstrg2);

    
    cotstr(IDa, idastr);
    cotstr(tkg, tkgstr);
    strxor3(HASH_LEN, idastr, randstrg1, tkgstr, xortemp);


    hash(xortemp, strlen(xortemp), hash_result);
    // hashbytes_to_big(HASH_LEN, hash_result, &temp1);
    // printf("h: ");
    // cotnum(temp1, stdout);

    // hashbytes_to_big(HASH_LEN, CMa, &temp1);
    // printf("CMa: ");
    // cotnum(temp1, stdout);

    strxor2(HASH_LEN, CMa, hash_result, ra2p);
    // hashbytes_to_big(HASH_LEN, ra2p, &temp2);
    // printf("ra2p: ");
    // cotnum(temp2, stdout);

    HAMC(HASH_LEN, tkg, IDa, randstrg1, CMa, CAap);
    // hashbytes_to_big(HASH_LEN, CAap, &temp1);
    // cotnum(temp1, stdout);

    cotstr(IDg, idgstr);
    strxor3(HASH_LEN, idgstr, randstrg1, tkgstr, xortemp);
    hash(xortemp, strlen(xortemp), hash_result);
    strxor2(HASH_LEN, randstrg2, hash_result, CMg);

    HAMC(HASH_LEN, tkg, IDg, randstrg1, CMg, CAg);
    // hashbytes_to_big(HASH_LEN, CAg, &temp1);
    // cotnum(temp1, stdout);

    //printf("Device sends ACK")
    unsigned char rg2p[HASH_LEN];
    unsigned char CAgp[HASH_LEN];

    strxor3(HASH_LEN, idgstr, randstra1, tkastr, xortemp);
    hash(xortemp, strlen(xortemp), hash_result);
    strxor2(HASH_LEN, CMg, hash_result, rg2p);

    HAMC(HASH_LEN, tkg, IDg, randstra1, CMg, CAgp);
    // hashbytes_to_big(HASH_LEN, CAg, &temp1);
    // cotnum(temp1, stdout);

    unsigned char seedastr[HASH_LEN];
    unsigned char seedgstr[HASH_LEN];
    cotstr(seeda, seedastr);
    cotstr(seedg, seedgstr);

    strxor2(HASH_LEN, seedastr, randstra2, seedastr);
    strxor2(HASH_LEN, tkastr, rg2p, tkastr);

    strxor2(HASH_LEN, seedgstr, ra2p, seedgstr);
    strxor2(HASH_LEN, tkgstr, randstrg2, tkgstr);

    gettimeofday(&end, NULL);
    printf("Continuous Authentication Time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    return 0;


}

void hash(unsigned char* ustr, int len, unsigned char* result)
{
    sha sh;
    int i;

    shs_init(&sh);
    for (i = 0; i < len; i++)
        shs_process(&sh, ustr[i]);
    shs_hash(&sh, result);
}

void h1(big id, epoint* Xi, epoint* Pi, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big big_Pi, big_Xi;

    big_Pi = mirvar(0);
    big_Xi = mirvar(0);

    cotstr(id, ustr);
    
    epoint_get(Xi, big_Xi, big_Xi);
    cotstr(big_Xi, ustr + strlen(ustr));

    epoint_get(Pi, big_Pi, big_Pi);
    cotstr(big_Pi, ustr + strlen(ustr));

    hash(ustr, strlen(ustr), result);
}

void h2(epoint* K1, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big x, y;

    x = mirvar(0);
    y = mirvar(0);

    epoint_get(K1, x, y);
    cotstr(x, ustr);
    cotstr(y, ustr + strlen(ustr));

    hash(ustr, strlen(ustr), result);
}


void h3(big ida, big idg, epoint* K1, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big x, y;

    x = mirvar(0);
    y = mirvar(0);

    cotstr(ida, ustr);
    cotstr(idg, ustr + strlen(ustr));

    epoint_get(K1, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    hash(ustr, strlen(ustr), result);
}

void h4(big ida, big idg, epoint* Sa, epoint* Sg, epoint* K1, epoint* K2, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big x, y;

    x = mirvar(0);
    y = mirvar(0);

    cotstr(ida, ustr);

    epoint_get(Sa, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    cotstr(idg, ustr + strlen(ustr));

    epoint_get(Sg, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(K1, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(K2, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    hash(ustr, strlen(ustr), result);
}

int get_biglen(big b)
{
    unsigned char ustrtemp[MAXLEN];
    // printf("%d ", big_to_bytes(MAXLEN, b, ustrtemp, 0));
    // printf("\n");
    return big_to_bytes(MAXLEN, b, ustrtemp, 0);
}

int get_pointlen(epoint* e)
{
    big big_ex, big_ey;

    big_ex = mirvar(0);
    big_ey = mirvar(0);
    epoint_get(e, big_ex, big_ey);
    return get_biglen(big_ex) + get_biglen(big_ey);
}

void print_point(epoint* e)
{
    big ex, ey;
    unsigned char buffer1[MAXLEN/2];
    unsigned char buffer2[MAXLEN/2];

    ex = mirvar(0);
    ey = mirvar(0);
    epoint_get(e, ex, ey);
    cotstr(ex, buffer1);
    cotstr(ey, buffer2);
    printf("[%s, %s]\n", buffer1, buffer2);
}

void hashbytes_to_big(int len, unsigned char* hashbytes, big* result)
{
    unsigned char* strbytes;
    int i;

    strbytes = (unsigned char*)malloc((len * 2 + 1)* sizeof(unsigned char));
    for(i = 0; i < len; i++)
        snprintf(strbytes + i * 2, (len -  i) * 2 + 1, "%02X", hashbytes[i]);
    cinstr(*result, strbytes);
}

void bigmod(big* b, big* modular)
{
    divide(*b, *modular, *modular);
}

void lrandom(big seed, int biglen, unsigned char* randstr)
{
    int r, i;
    unsigned* uptr;
    int* rptr;
    big t;

    t = mirvar(0);

    rptr = (int*)randstr;
    uptr = (unsigned*)seed;
    for (i = 0; i < biglen/sizeof(unsigned); i++)
    {
        srand(uptr[i]);
        r = rand();
        rptr[i] = r;
    }
    // hashbytes_to_big(HASH_LEN, randstr, &t);
    // cotnum(t, stdout);
}

void urandom(int biglen, unsigned char* randstr)
{
    int r, i;
    int* rptr;

    rptr = (int*)randstr;
    srand(time(NULL));
    for (i = 0; i < biglen/sizeof(int); i++)
    {
        r = rand();
        rptr[i] = r;
    }
}

void strxor2(int len, unsigned char* str1, unsigned char* str2, unsigned char* xorresult)
{
    int i;
    for (i = 0; i < len; i++)
    {
        xorresult[i] = str1[i]^str2[i];
        //printf("--%02X", xorresult[i]);
    }
    //printf("\n");    
}

void strxor3(int len, unsigned char* str1, unsigned char* str2, unsigned char* str3, unsigned char* xorresult)
{
    int i;
    for (i = 0; i < len; i++)
    {
        xorresult[i] = str1[i]^str2[i]^str3[i];
    }
}

void HAMC(int len, big tk, big id, unsigned char* ra1, unsigned char* CMa, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];

    cotstr(tk, ustr);
    cotstr(id, ustr + strlen(ustr));

    strncpy(ustr + strlen(ustr), ra1, len);
    strncpy(ustr + strlen(ustr), CMa, len);

    hash(ustr, strlen(ustr), result);
}