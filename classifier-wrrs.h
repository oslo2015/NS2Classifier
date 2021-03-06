/*

实现：
(1)fat tree 拓扑， 用 k 值来设置。
(2)实现packet-base转发。
(3) wrrLast[]初始化时，做了优化，不是都是0，而是类wrr的初始化。
例如当k = 4时， 初始化为  0 1 0 1


缺陷：


*/


#include "config.h"
#include "packet.h"
#include "ip.h"
#include "classifier.h"
#include <stdio.h>
#include <string.h>

/// SearchTable START
#define ST_OK				1
#define ST_ERR				-1
#define ST_DONOTHING		-3
#define ST_NOTFOUND			-2

class SearchTable {
public :
    SearchTable();
    ~SearchTable();
    int insertTable(int key);
    int findKey(int key);
    int removeTable(int key);
    int clearTable();
    int reallocTable(int newNum);
    void printTable();

protected:
    int top;
    int totalNum;

private:
    int *table;
};
/// SearchTable END


#define SWITCH_HOST     1
#define SWITCH_CORE     2
#define SWITCH_AGG      3
#define SWITCH_EDGE     4
#define SWITCH_NC		-1

#define WRRS_OK			1
#define WRRS_ERROR		0

#define PODRR			1
#define HOSTRR			2
#define ONERR			3


class WRRSClassifier : public Classifier {
public :
    WRRSClassifier();
    ~WRRSClassifier();
    void recv(Packet* p, Handler*h);
    virtual int classify(Packet *);

    /// packet tag
    void insertTag(int tag)    {
        packetTag.insertTable(tag);
    }
    void removeTag(int tag)    {
        packetTag.removeTable(tag);
    }

    void setNodeInfo(int podid, int inpodid, int type, int agg);
    void setTagSection(int sec);
    void setNodeType(int type) {NodeType = type;}
    void printNodeInfo();
    void initLast();
    //void setRRSTD(int lastType);

protected:

    virtual int command( int argc, const char*const* argv);
    virtual int addrToPodId( int addr);
    virtual int addrToSubnetId( int addr);
    int fatTreeK( int k);

    int schedule(int podid, int fid, int addr);
    int nextWRR(int rrNum, int MOL);

    /// packet tag
    SearchTable packetTag;

private:
    int NodeId;

    int PodId;
    int InPodId;
    int NodeType;
    int aggShift;  			/// edge使用该变量，记录该pod第一个agg switch的id。

    int hostShift;  		/// host addr的偏移量，用于计算podId。(k决定)
    int hostNumInPod;           	/// (k决定)
    int eachSide;                   /// (k决定)
    int *wrrLast;                   ///(k决定)
    int fatK;                       ///(k决定)

    int numForNotTag;


    //bool podRR;
    //bool hostRR;
    //bool oneRR;
    int 	RRNum;
};
