#include <iostream>
using namespace std;

int main() {
    long long a=1,b=2,c=3,d=4,e=5,f=6;

    for(int i=0;i<100000;i++) {
        a += b;
        c += d;
        e += f;
        b += a;
        d += c;
        f += e;
    }

    cout << a+c+e << endl;
}
