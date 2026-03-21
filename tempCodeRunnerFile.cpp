#include <bits/stdc++.h>
using namespace std;

struct Edge {
    int cost;
    bool isEven;
};

int main(){
    int n;
    cin>>n;

    vector<int>L(n);
    for(int i=0;i<n;i++) cin>>L[i];

    vector<Edge> edges;

    for(int i=0;i<n;i++){
        for(int j=0;j<i;j++){
            if(L[i] != L[j]){
                int cost = abs(L[i]-L[j]);
                edges.push_back({cost, cost%2==0});
            }
        }
    }

    sort(edges.begin(), edges.end(), [](Edge &a, Edge &b){
        return a.cost < b.cost;
    });

    int even=0, odd=0;
    int ans=0;

    for(auto &e:edges){
        if(e.isEven){
            ans += e.cost;
            even++;
        }
        else{
            if(even > odd){
                ans += e.cost;
                odd++;
            }
        }
    }

    if(even + odd == 0) cout<<-1;
    else cout<<ans;
}