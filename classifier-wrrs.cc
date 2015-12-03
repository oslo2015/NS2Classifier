#include "classifier-wrrs.h"

/// SearchTable
SearchTable::SearchTable() {
	top = 0;
	totalNum = 0;
	table = NULL;
}

SearchTable::~SearchTable() {
	clearTable();
}

int SearchTable::clearTable() {
	top = 0;
	totalNum = 0;
	if (NULL != table) {
		delete[] table;
	}
	table = NULL;
	return ST_OK;
}

int SearchTable::insertTable(int key) {
	if (top >= totalNum) {
		if (ST_ERR == reallocTable(totalNum + 5))
			return ST_ERR;
	}
	table[top] = key;
	++top;
	return ST_OK;
}

int SearchTable::findKey(int key) {
	int i;
	for (i = 0; i < top; ++i) {
		if (key == table[i]) {
			return i;
		}
	}
	return ST_NOTFOUND;
}

int SearchTable::reallocTable(int newNum) {
	int *a = new int[newNum];
	if (NULL == a)
		return ST_ERR;
	if (NULL != table) {
		int i;
		for (i = 0; i < totalNum; ++i)
			a[i] = table[i];
		delete[] table;
		for (i = totalNum; i < newNum; ++i)
			a[i] = 0;
	}
	table = a;
	totalNum = newNum;
	return ST_OK;
}

int SearchTable::removeTable(int key) {
	int i = findKey(key);
	if (ST_NOTFOUND != i) {
		if (i != top - 1) {
			table[i] = table[top - 1];
		}
		--top;
		return ST_OK;
	}
	return ST_DONOTHING;
}

void SearchTable::printTable() {
	int i;
	printf("\ntop : %d   total : %d\n", top, totalNum);
	for (i = 0; i < top; ++i) {
		printf("%d  ", table[i]);
	}
	printf("\n");
}

/// SearchTable

static class WRRSClassifierClass: public TclClass {
public:
	WRRSClassifierClass() :
			TclClass("Classifier/WRRS") {
	}
	TclObject* create(int, const char* const *) {
		return (new WRRSClassifier());
	}
} class_wrrs_classifier;

WRRSClassifier::WRRSClassifier() {
	bind("wtid_", &NodeId);

	PodId = -1;
	InPodId = -1;
	NodeType = SWITCH_NC;
	aggShift = -1;

	hostShift = -1;
	hostNumInPod = -1;
	eachSide = -1;
	wrrLast = NULL;
	fatK = -1;
	numForNotTag = -1;

	flowBased = false;
	pathList = NULL;
	pathListNum = -1;
	//podRR = false;
	//hostRR = false;
	//oneRR = false;
	RRNum = 0;
}

WRRSClassifier::~WRRSClassifier() {
	if (NULL != wrrLast) {
		delete[] wrrLast;
		wrrLast = NULL;
	}
	if (NULL != pathList) {
		delete[] pathList;
		pathList = NULL;
	}
}

/// 设置拓扑的参数
int WRRSClassifier::fatTreeK(int k) {
	fatK = k;
	hostNumInPod = k * k / 4;
	eachSide = k / 2;
	hostShift = 5 * k * k / 4;
	numForNotTag = k / 2;

	if (NULL != wrrLast)
		delete[] wrrLast;
	RRNum = fatK * hostNumInPod;
	if (NULL == (wrrLast = new int[RRNum])) {
		printf("null pointer in WRRSClassifier::fatTreeK().\n");
	}
	initLast();

	return WRRS_OK;
}

int WRRSClassifier::addrToPodId(int addr) {
	return (addr) / hostNumInPod;
}

int WRRSClassifier::addrToSubnetId(int addr) {
	int subnetNum = eachSide;
	return ((addr) % hostNumInPod) / subnetNum;
}

int WRRSClassifier::classify(Packet *p) {
	/// 与自带的 AddressClassifier 一样，
	/// 由于AddressClassifier只是重载了classify()，
	/// 这样使WRRSClassifier拥有AddressClassifier
	/// 相同的功能。

	hdr_ip* iph = hdr_ip::access(p);
	return mshift(iph->daddr());

}

void WRRSClassifier::recv(Packet* p, Handler*h) {
	/// 该classifier所在结点是 host。
	if (SWITCH_HOST == NodeType) {
		Classifier::recv(p, h);
	}

	/// 该classifier所在结点是 core switch。
	else if (SWITCH_CORE == NodeType) {
		Classifier::recv(p, h);
	}

	/// 该classifier所在结点是 aggregation switch。
	else if (SWITCH_AGG == NodeType) {
		hdr_ip* iph = hdr_ip::access(p);    /// 获得ip包头

		int p_fid = iph->flowid();
		int p_addr = iph->daddr() - hostShift;
		int p_podid = addrToPodId(p_addr);

		if (p_podid != PodId) {	/// 目的地址不在本pod， upstream。
			int nextNode = schedule(p_podid, p_fid, p_addr);
			NsObject* node = NULL;
			Tcl& tcl = Tcl::instance();
			//[Simulator instance]获取当前实例
			tcl.evalf("[Simulator instance] get-link-head %d %d", NodeId,
					nextNode);
			//获取链路nid- nextDst对象的指针
			node = (NsObject*) TclObject::lookup(tcl.result());
			node->recv(p, h);
		} else {	/// 目的地址在本pod，默认的路由即可(downStream)。
			Classifier::recv(p, h);
		}

	}

	/// 该classifier所在结点是 edge switch。
	else if (SWITCH_EDGE == NodeType) {
		hdr_ip* iph = hdr_ip::access(p);    /// 获得ip包头

		int p_fid = iph->flowid();
		int p_addr = iph->daddr() - hostShift;
		int p_podid = addrToPodId(p_addr);
		int p_subnetid = addrToSubnetId(p_addr);

		if (p_podid != PodId) {	 /// 目的地址不在本pod， upstream。
			int nextNode = schedule(p_podid, p_fid, p_addr);
			NsObject* node = NULL;
			Tcl& tcl = Tcl::instance();
			//[Simulator instance]获取当前实例
			tcl.evalf("[Simulator instance] get-link-head %d %d", NodeId,
					nextNode);
			//获取链路nid- nextDst对象的指针
			node = (NsObject*) TclObject::lookup(tcl.result());
			node->recv(p, h);
		} else if (InPodId != p_subnetid) {	 /// 目的地址不在本edge switch， upstream。
			int nextNode = schedule(p_podid, p_fid, p_addr);
			NsObject* node = NULL;
			Tcl& tcl = Tcl::instance();
			//[Simulator instance]获取当前实例
			tcl.evalf("[Simulator instance] get-link-head %d %d", NodeId,
					nextNode);
			//获取链路nid- nextDst对象的指针
			node = (NsObject*) TclObject::lookup(tcl.result());
			node->recv(p, h);
		} else {	/// 目的地址与该edge switch直接相连，默认路由即可(downStream)。
			Classifier::recv(p, h);
		}
	}

	/// 该classifier设置结点类型时出错，
	/// 则按照AddrClassifier的方式转发。
	else {
		if (SWITCH_NC != NodeType) {
			printf("%d\n", NodeType);
		}
		Classifier::recv(p, h);
	}
}

int WRRSClassifier::nextWRR(int rrNum, int MOL) {
	int next = wrrLast[rrNum] % (MOL);
	wrrLast[rrNum] = (next + 1) % (MOL);
	return next;
}

/// upstreams时，对switch的选择
int WRRSClassifier::schedule(int podid, int fid, int addr) {
	int next;

	/// agg switch直接Round-Robin
	if (SWITCH_AGG == NodeType) {
		if (true == flowBased) {
			int findPath = findFidAmongList_index(fid);
			next = aggShift + (-1 == findPath ? 0 : findPath);
		} else {
			next = InPodId * eachSide + nextWRR(addr, eachSide);
		}

	}

	/// edge switch
	else if (SWITCH_EDGE == NodeType) {
		if (numForNotTag == eachSide) {
			/// 每条路都可用
			if (true == flowBased) {
				int findPath = findFidAmongList_index(fid);
				next = aggShift + (-1 == findPath ? 0 : findPath);
				//printf("fid = %d, next = %d\n", fid, next);
			} else {
				next = aggShift + nextWRR(addr, eachSide);
				//printf("%d,\t%d,\t%d\n", aa, NodeId, addr);
			}

		} else {
			if (ST_NOTFOUND == packetTag.findKey(fid)) {
				next = aggShift + nextWRR(addr, numForNotTag);
				//printf("%d\n", next);
			} else {
				next = aggShift + numForNotTag
						+ nextWRR(addr, eachSide - numForNotTag);
			}
		}
	}

	return next;
}

void WRRSClassifier::setTagSection(int sec) {
	numForNotTag = eachSide - sec;
///printf("%d----%d\n", numForNotTag, sec);
}

void WRRSClassifier::setNodeInfo(int podid, int inpodid, int type, int agg) {
	PodId = podid;
	InPodId = inpodid;
	NodeType = type;
	aggShift = agg;
///printf("%d,\t%d\n", aggShift, NodeId);
}

void WRRSClassifier::setFlowBased(int flag) {
	if (FLOWBASED == flag) {
		flowBased = true;
		pathListNum = eachSide;
		pathList = new INTLIST[pathListNum];
	} else if (NOTFLOWBASED == flag) {
		flowBased = false;
		if (NULL != pathList) {
			int i;
			for (i = 0; i < pathListNum; ++i) {
				pathList[i].clear();
			}
			delete[] pathList;
			pathList = NULL;
		}
		pathListNum = -1;
	}

}

void WRRSClassifier::initLast() {
	wrrLast[0] = 0;
	int i;
	for (i = 1; i < RRNum; ++i) {
		wrrLast[i] = (wrrLast[i - 1] + 1) % eachSide;
	}
}

/*
 void WRRSClassifier::setRRSTD(int lastType)
 {
 if(NULL != wrrLast)
 delete[] wrrLast;
 if(PODRR == lastType)
 {
 RRNum = fatK;
 }
 else if(HOSTRR == lastType)
 {
 RRNum = fatK * hostNumInPod;
 }
 else if(ONERR == lastType)
 {
 RRNum = 1;
 }
 else			/// 默认是podrr
 {
 RRNum = fatK;
 }
 if(NULL == (wrrLast = new int[RRNum]))
 {
 printf("Allocate failed in setlastType().\n");
 //return WRRS_ERROR;
 }
 initLast();
 }
 */

int WRRSClassifier::addFlowId(int fid) {
	int findPath = -1;
	if (false == flowBased) {
		printf("not flow based but still add fid!");
		findPath = -1;
	} else {
		findPath = findMinSizeAmongList_index(pathList, pathListNum);
		if (-1 == findPath) {
			printf("flow based path record wrong!");
		} else {
			pathList[findPath].push_back(fid);
		}
		/// printf("!");
	}
	Tcl& tcl = Tcl::instance();
	tcl.resultf("%d", (-1 == findPath) ? -1 : aggShift + findPath);
	return findPath;
}

void WRRSClassifier::removeFlowId(int fid) {
	int findPath = -1;
	if (false == flowBased)
		printf("not flow based but still add fid!");
	else if (NULL == pathList || pathListNum <= 0)
		printf("null pointer or wrong listNum");
	else {
		int i;
		for (i = 0; i < pathListNum; ++i) {
			if (true == findInList(pathList[i], fid)) {
				pathList[i].remove(fid);
				findPath = i;
				break;
			}
		}
	}
	Tcl& tcl = Tcl::instance();
	tcl.resultf("%d", (-1 == findPath) ? -1 : aggShift + findPath);
}

int WRRSClassifier::findFidAmongList_index(int fid) {
	if (false == flowBased) {
		printf("not flow based but still add fid!");
		return -1;
	} else if (NULL == pathList || pathListNum <= 0) {
		printf("null pointer or wrong listNum");
		return -1;
	}

	int i;
	for (i = 0; i < pathListNum; ++i) {
		if (true == findInList(pathList[i], fid))
			return i;
	}
	return -1;
}

void WRRSClassifier::findNextIdByFid(int fid) {
	Tcl& tcl = Tcl::instance();
	int findPath = findFidAmongList_index(fid / 1000);
	if (-1 == findPath) {
		tcl.resultf("%d", -1);
	} else {
		tcl.resultf("%d", aggShift + findPath);
	}

}

void WRRSClassifier::printNodeInfo() {
	if (SWITCH_HOST == NodeType) {
		printf("\nHost:\nnode id : %d\n", NodeId);
	}

	else if (SWITCH_CORE == NodeType) {
		printf("\ncore switch:\nnode id : %d\n", NodeId);
	}

	else if (SWITCH_AGG == NodeType) {
		printf("\nagg switch:\nnode id : %d\n", NodeId);
		printf("pod id : %d\n", PodId);
		printf("in pod id : %d\n", InPodId);
		printf("hostShift : %d\n", hostShift);
		printf("hostNumInPod : %d\n", hostNumInPod);
		printf("eachSide : %d\n", eachSide);
		printf("fatK : %d\n", fatK);
		printf("numForNotTag : %d\n", numForNotTag);
		printf("flowBased : %d\n", flowBased);
		printf("pathListNum : %d\n", pathListNum);
		int nn = fatK / 2;
		int cal1 = (NodeId - nn * nn) / nn;
		int cal2 = (NodeId - nn * nn) % nn;
		if (cal1 == PodId) {
			printf("yes.\n");
		} else {
			printf("no.\n");
		}
		if (cal2 == InPodId) {
			printf("yes.\n");
		} else {
			printf("no.\n");
		}
	}

	else if (SWITCH_EDGE == NodeType) {
		printf("\nedge switch:\nnode id : %d\n", NodeId);
		printf("pod id : %d\n", PodId);
		printf("in pod id : %d\n", InPodId);
		printf("hostShift : %d\n", hostShift);
		printf("hostNumInPod : %d\n", hostNumInPod);
		printf("eachSide : %d\n", eachSide);
		printf("fatK : %d\n", fatK);
		printf("aggShift : %d\n", aggShift);
		printf("numForNotTag : %d\n", numForNotTag);
		printf("flowBased : %d\n", flowBased);
		printf("pathListNum : %d\n", pathListNum);
		int nn = fatK / 2;
		int cal1 = (NodeId - nn * nn - fatK * nn) / nn;
		int cal2 = (NodeId - nn * nn) % nn;
		int cal3 = PodId * nn + nn * nn;
		if (cal1 == PodId) {
			printf("yes.\n");
		} else {
			printf("no.\n");
		}
		if (cal2 == InPodId) {
			printf("yes.\n");
		} else {
			printf("no.\n");
		}
		if (cal3 == aggShift) {
			printf("yes.\n");
		} else {
			printf("no.\n");
		}
	}

	else if (SWITCH_NC == NodeType) {
		printf("\nhehe.\n");
	}

	else {
		printf("\nhehe.\n");
	}
}

int WRRSClassifier::command(int argc, const char* const * argv) {
	/**
	 $classifier setNodeInfo podid inpodid type aggshift
	 $classifier setFatTreeK  k
	 $classifier insertTag   tag
	 $classifier removeTag tag
	 $classifier setTagSection  sec
	 $classifier setNodeType type
	 $classifier setRRType type

	 $classifier printNodeInfo
	 $classifier resetLast

	 $classifier setFlowBased	0/1
	 $classifier addFlowId		fid
	 $classifier removeFlowId	fid
	 $classifier findNextIdByFid	fid

	 */
//Tcl& tcl = Tcl::instance();
	if (argc == 2) {
		if (strcmp(argv[1], "printNodeInfo") == 0) {
			printNodeInfo();
			return (TCL_OK);
		}

		if (strcmp(argv[1], "resetLast") == 0) {
			initLast();
			return (TCL_OK);
		}

	} else if (argc == 3) {
		if (strcmp(argv[1], "setFatTreeK") == 0) {
			int key = atoi(argv[2]);
			fatTreeK(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "insertTag") == 0) {
			insertTag(int(atoi(argv[2])));
			//packetTag.printTable();
			return (TCL_OK);
		}

		if (strcmp(argv[1], "removeTag") == 0) {
			removeTag(int(atoi(argv[2])));
			return (TCL_OK);
		}

		if (strcmp(argv[1], "setTagSection") == 0) {
			int key = atoi(argv[2]);
			//printf("^^^%d\n", key);
			setTagSection(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "setNodeType") == 0) {
			int key = atoi(argv[2]);
			setNodeType(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "setFlowBased") == 0) {
			int key = atoi(argv[2]);
			setFlowBased(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "addFlowId") == 0) {
			int key = atoi(argv[2]);
			addFlowId(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "removeFlowId") == 0) {
			int key = atoi(argv[2]);
			removeFlowId(key);
			return (TCL_OK);
		}

		if (strcmp(argv[1], "findNextIdByFid") == 0) {
			int key = atoi(argv[2]);
			findNextIdByFid(key);
			return (TCL_OK);
		}

		/*
		 if (strcmp(argv[1], "setRRType") == 0)
		 {
		 int key = atoi(argv[2]);
		 setRRSTD(key);
		 return (TCL_OK);
		 }
		 */
	} else if (argc == 6) {
		if (strcmp(argv[1], "setNodeInfo") == 0) {
			int podid = atoi(argv[2]);
			int inpodid = atoi(argv[3]);
			int type = atoi(argv[4]);
			int agg = atoi(argv[5]);
			setNodeInfo(podid, inpodid, type, agg);
			return (TCL_OK);
		}
	}
	return (Classifier::command(argc, argv));
}

bool findInList(INTLIST l, int key) {
	INTLIST::iterator it = find(l.begin(), l.end(), key);
	if (l.end() == it)
		return false;
	return true;
}

int findMinSizeAmongList_index(INTLIST * llist, int listNum) {
	if (NULL == llist || listNum <= 0)
		return -1;
	int min = llist[0].size();
	int index = 0;
	int i;
	for (i = 1; i < listNum; ++i) {
		if (llist[i].size() < min) {
			min = llist[i].size();
			index = i;
		}
	}
	return index;
}

