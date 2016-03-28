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
#include "tcp.h"
#include "classifier.h"
#include <stdio.h>
#include <string.h>

/**
 * stl list
 * */
#include <iostream>
#include <list>
#include <algorithm>

using namespace std;

typedef list<int> INTLIST;

bool findInList(INTLIST l, int key);
int findMinSizeIndexAmongList(INTLIST * llist, int listNum);
int addAmongLists(INTLIST * llist, int listNum, int key);
int removeAmongLists(INTLIST * llist, int listNum, int key);
int findIndexAmongLists(INTLIST * llist, int listNum, int key);

int newIntLists(INTLIST * &llist, int listNum);
int destoryIntLists(INTLIST * &llist, int &listNum);
int printIntLists(INTLIST * &llist, int &listNum);

/// SearchTable START
#define ST_OK				1
#define ST_ERR				-1
#define ST_DONOTHING		-3
#define ST_NOTFOUND			-2

class SearchTable {
public:
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

#define FLOWBASED		1
#define NOTFLOWBASED	0

#define NON_LINK		0
#define CORE_LINK		1
#define AGG_LINK		2

class WRRSClassifier: public Classifier {
public:
	WRRSClassifier();
	~WRRSClassifier();
	void recv(Packet* p, Handler*h);
	virtual int classify(Packet *);

	/// packet tag
	void insertTag(int tag) {
		packetTag.insertTable(tag);
	}
	void removeTag(int tag) {
		packetTag.removeTable(tag);
	}

	void setNodeInfo(int podid, int inpodid, int type, int agg);
	void setTagSection(int sec);
	void setNodeType(int type) {
		NodeType = type;
	}
	void printNodeInfo();
	void initLast();

	/*	设置 flow-based scheduling,
	 * 	flag== 1 设置成 flowbased
	 * 	feedBack== 1 分配 pathList4fb
	 * */
	void setFlowBased(int flag, int feedBack);
	/*
	 * feedBack== 1  从pathList4fb中查找
	 * */
	int addFlowId(int fid, int feedBack);
	void removeFlowId(int fid, int feedBack);
	int findFidIndexAmongLists(int fid, int feedBack);
	void findNextIdByFid(int fid, int feedBack);	/// 通过c++向tcl传递结果
	//void setRRSTD(int lastType);

	void getFlowNum();

	void enableLinkFailure(int linkType, int linkSrcId, int linkDstId,
			int podNumForLFDown);
	void disableLinkFailure();

protected:

	virtual int command(int argc, const char* const * argv);
	virtual int addrToPodId(int addr);
	virtual int addrToSubnetId(int addr);
	int fatTreeK(int k);

	int schedule(int podid, int fid, int addr, int feedBack);
	int nextWRR(int rrNum, int MOL);
	int nextWRR(int rrNum, int MOL, int exclude);

	/// packet tag
	SearchTable packetTag;

private:
	int NodeId;

	int PodId;
	int InPodId;
	int NodeType;
	int aggShift;  			/// agg,edge使用该变量，记录该pod第一个agg switch的id。

	int hostShift;  		/// host addr的偏移量，用于计算podId。(k决定)
	int hostNumInPod;           	/// (k决定)
	int eachSide;                   /// (k决定)
	int *wrrLast;                   ///(k决定)
	int fatK;                       ///(k决定)

	int numForNotTag;

	bool flowBased;
	INTLIST * pathList;		/// 用于记录各个流下一条的位置, tcp发送包
	int pathListNum;
	INTLIST * pathList4fb;		/// 用于记录各个流下一条的位置, tcp ack包
	int pathList4fbNum;
	//bool podRR;
	//bool hostRR;
	//bool oneRR;
	int RRNum;

	bool isLinkFailure;
	int linkFailureType;
	// 这里规定srcid比dstid大。
	int linkSrcId;
	int linkDstId;
	int linkDstSubId;
	int podNumForLFDown;
};
