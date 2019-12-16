import * as utils from  "./utils";
import * as android from "./android";
import { BaseConfig } from "./config";

const THRESHOLD = 1000;

interface IRuns {
  [addr: string] : Run;
}

interface ITcaches {
  [tid: string] : Tcache;
}

export class JemallocInfo {
  constructor(public region: Region,
              public run: Run,
              public chunk: Chunk,
              public addr: NativePointer) {}

  dump() {
    console.log("[*] Jemalloc info of " + this.addr);
    if (this?.chunk) {
      console.log(" Chunk:");
      console.log("  Address : " + this.chunk.addr);
      console.log("  Size    : 0x" + this.chunk.size.toString(16));
    }
    if (this?.run) {
      console.log(" Run:");
      console.log("  Address : " + this.run.addr);
      console.log("  Size    : 0x" + this.run.size.toString(16));
    }
    if (this?.region) {
      console.log(" Region:");
      console.log("  Address : " + this.region.addr);
      console.log("  Size    : 0x" + this.region.size.toString(16));
    }
  }
}

export class Jemalloc {
  nBins: number;
  binInfo: BinInfo[] = [];
  tbinInfo: TBinInfo[] = [];
  chunks: Chunk[] = [];
  arenas: Arena[] = [];
  runs: IRuns = {};
  tcaches: ITcaches = {};
  private config: BaseConfig;
  private arenasAddr: NativePointer[] = [];
  private nArenas: number;
  private chunkSize: number;
  private threshold: number = THRESHOLD;
  private counter: number = 0;

  constructor(config: BaseConfig) {
    if (config === null || config === undefined) {
      console.log("[-] frida-jemalloc could not detect any config");
      return;
    }

    this.config = config;
    this.nBins = <number> utils.calculateNBins();

    const arenasArrAddr = utils.addressSymbols(['arenas', 'je_arenas']).readPointer();
    this.nArenas = utils.addressSymbols(['narenas', 'narenas_total','je_narenas_total']).readU32();

    this.arenasAddr = utils.readPointers(arenasArrAddr, this.nArenas);
    this.chunkSize = utils.addressSymbols(['chunksize', 'je_chunksize']).readU32();

    // Parses this only once as these structures are read only
    this.parseBinInfo();
    this.parseTbinInfo();
  }

  parse() {
    this.counter = 0;

    if (this?.config) {
      this.parseChunks();
      this.parseAllRuns();
    }
  }

  parseAll() {
    if (this?.config) {
      this.parse();
      this.parseArenas();
      this.parseTcaches();
    }
  }

  parseBinInfo() {
    let infoAddr = utils.addressSymbols(["je_arena_bin_info"]);
    const infoSize = this.config.sizeOf("arena_bin_info_t");

    for (var i = 0; i < this.nBins; i++) {
      const regSize = <number><unknown>this.config.offsetStructMember(infoAddr, "arena_bin_info_t", "reg_size").readU64();
      const runSize = <number><unknown>this.config.offsetStructMember(infoAddr, "arena_bin_info_t", "run_size").readU64();
      const regOff = this.config.offsetStructMember(infoAddr, "arena_bin_info_t", "reg0_offset").readU32();
      const nRegs = this.config.offsetStructMember(infoAddr, "arena_bin_info_t", "nregs").readU32();

      this.binInfo.push(new BinInfo(regSize, runSize, regOff, nRegs));

      infoAddr = infoAddr.add(infoSize);
    }
  }

  parseTbinInfo() {
    const nhbins = utils.addressSymbols(["je_nhbins", "nhbins"]).readU32();
    let tcacheBinInfo = utils.addressSymbols(["je_tcache_bin_info"]).readPointer();

    for (var i = 0; i < nhbins; i++) {
      const ncached = tcacheBinInfo.readU32();
      tcacheBinInfo = tcacheBinInfo.add(4);

      this.tbinInfo.push(new TBinInfo(ncached));
    }
  }

  parseChunks() {
    const chunksRtreeAddr = utils.addressSymbols(["je_chunks_rtree"]);
    const maxHeight = this.config.offsetStructMember(chunksRtreeAddr, "rtree_t", "height").readU32();
    const levelsAddr = chunksRtreeAddr.add(this.config.offsetOf("rtree_t", "levels"));
    const rtreeLevelsSize = this.config.sizeOf("rtree_level_t");
    let root;
    let stack = [];

    let lvlAddr = levelsAddr;
    for (var i = 0; i < maxHeight; i++) {
      const addr = this.config.offsetStructMember(lvlAddr, "rtree_level_t", "subtree").readPointer();
      if (addr.equals(0)) {
        lvlAddr = lvlAddr.add(rtreeLevelsSize);
        continue;
      }

      root = [addr, i];
      break;
    }

    stack.push(root);

    this.chunks = [];

    while (stack.length > 0) {
      let element = stack.pop();
      let node = element[0];
      const height = element[1];

      const curLevelAddr = levelsAddr.add(height * rtreeLevelsSize);
      const bits = curLevelAddr.add(this.config.offsetOf("rtree_level_t", "bits")).readU32();
      const maxKey = 1 << bits;

      for (let i = 0; i < maxKey; i++) {
        const addr = node.readPointer();
        node = node.add(8);

        if (addr.equals(0))
          continue;

        if (height === maxHeight - 1) {
          const nodeAddr = addr.add(this.config.offsetOf("arena_chunk_t", "node"));
          const arenaAddr = nodeAddr.add(this.config.offsetOf("extent_node_t", "en_arena")).readPointer();

          if (<number><unknown> addr & 0xfff) {
            continue;
          }

          if (this.arenasAddr.some(x => x.equals(arenaAddr))) {
            this.chunks.push(new Chunk(addr, arenaAddr, [], this.chunkSize));
          } else {
            this.chunks.push(new Chunk(addr, ptr(0), [], this.chunkSize));
          }
        } else {
          stack.push([addr, height + 1]);
        }
      }
    }
  }

  parseAllRuns() {
    const mapBias = utils.addressSymbols(["je_map_bias"]).readU32();
    const chunkNPages = this.chunkSize >> 12;
    const chunkMapDwords = Math.floor(this.config.sizeOf("arena_chunk_map_bits_t") / utils.dwordSize);
    const bitMapCount = (chunkNPages - mapBias) * chunkMapDwords;
    const mapMiscOffset = utils.addressSymbols(["je_map_misc_offset"]).readU64();
    const mapMiscSize = this.config.sizeOf("arena_chunk_map_misc_t")
    const runOff = this.config.offsetOf("arena_chunk_map_misc_t", "run");
    // the 12 least significant bits of each bitmap entry hold
    // various flags for the corresponding run
    const flagsMask = (1 << 12) - 1;

    this.runs = {};

    for (var i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];

      if (chunk.arenaAddr.equals(0))
        continue;

      const nodeOff = this.config.offsetOf("arena_chunk_t", "node");
      const enAddrOff = this.config.offsetOf("extent_node_t", "en_addr");
      const enAddr = chunk.addr.add(nodeOff).add(enAddrOff).readPointer();

      if (!enAddr.equals(chunk.addr)) {
        continue;
      }

      const bitMapAddr = this.config.offsetStructMember(chunk.addr, "arena_chunk_t", "map_bits");
      const bitMap = utils.readPointers(bitMapAddr, bitMapCount);

      for (var j = 0; j < bitMap.length; j++) {
        const mapElm = <number><unknown> bitMap[j];
        let binSize;
        let binId;

        if ((mapElm & 0xf) === 1) {
          // Small allocation
          let offset;
          if (this.config.version === "6") {
            offset = mapElm & ~flagsMask;
            binId = (mapElm & 0xff0) >> 4;
          } else {
            offset = (mapElm & ~0x1fff) >> 1;
            binId = (mapElm & 0x1fe0) >> 5;
          }

          binSize = this.binInfo[binId].runSize;
          // part of the previous run
          if (offset != 0 || binSize.equals(0)) {
            continue;
          }

        } else if ((mapElm & 0xf) === 3) {
          // Large allocations
          if (this.config.version === "6") {
            binSize = mapElm & ~flagsMask;
          } else {
            binSize = (mapElm & ~0x1fff) >> 1;
          }

          if (binSize === 0) {
            continue;
          }
          binId = -1;

        } else {
          continue;
        }

        const mapMiscAddr = chunk.addr.add(mapMiscOffset);
        const curArenaChunkMapMisc = mapMiscAddr.add(j * mapMiscSize);
        const hdrAddr = curArenaChunkMapMisc.add(runOff);
        const addr = chunk.addr.add((j + mapBias) * utils.pageSize);

        if (hdrAddr.equals(0)) {
          continue;
        }

        const run = this.parseRun(hdrAddr, addr, binSize, binId);

        if (run !== null) {
          this.runs[hdrAddr.toString()] = run;
          chunk.runs.push(run);
        }
      }
    }
  }

  parseArenas() {
    const binSize = this.config.sizeOf("arena_bin_t");

    this.arenas = [];

    for (var i = 0; i < this.nArenas; i++) {
      const curArenaBinAddr = this.arenasAddr[i].add(this.config.offsetOf("arena_t", "bins"));

      if (curArenaBinAddr.equals(0)) {
        continue;
      }

      const arena = new Arena(this.arenasAddr[i], curArenaBinAddr, i, [], [], []);

      for (var j = 0; j < this.nBins; j++) {
        const binAddr = curArenaBinAddr.add(j * binSize);
        const runCur = this.config.offsetStructMember(binAddr, "arena_bin_t", "runcur").readPointer();
        let run;

        if (runCur.equals(0)) {
          run = null;
        } else {
          run = this.runs[runCur.toString()];
        }

        arena.bins.push(new ArenaBin(binAddr, j, run));
      }

      this.arenas.push(arena);
    }
  }

  parseTcaches() {
    const nhbins = utils.addressSymbols(["je_nhbins", "nhbins"]).readU32();
    let maxCached = 0;

    this.tcaches = {};

    for (var i = 0; i < this.tbinInfo.length; i++) {
      maxCached = maxCached + this.tbinInfo[i].ncachedMax;
    }

    let tcacheSize = this.config.offsetOf("tcache_t", "tbins") +
      (this.config.sizeOf("tcache_bin_t") * nhbins) +
      (maxCached * utils.dwordSize);

    tcacheSize = this.sizeToBinSize(tcacheSize);

    const dataOff = this.config.offsetOf("pthread_key_data_t", "data");
    const pthreadInternalSize = this.config.sizeOf("pthread_internal_t");
    const keyDataOff = this.config.offsetOf("pthread_internal_t", "key_data");
    const pthreadKeyDataSize = this.config.sizeOf("pthread_key_data_t");
    const BIONIC_PTHREAD_KEY_COUNT = 141;

    // g_thread_list points to the first pthread_internal_t struct
    let pthreadInternal = utils.addressSymbols(["_ZL13g_thread_list"]).readPointer();
    while (!pthreadInternal?.equals(0)) {
      let tcacheArena;
      let tsdDwords;
      const tid = this.config.offsetStructMember(pthreadInternal, "pthread_internal_t", "tid").readU32();
      let keyData = pthreadInternal.add(keyDataOff);

      // Point to the next pthreadInternal
      pthreadInternal = this.config.offsetStructMember(pthreadInternal, "pthread_internal_t", "next").readPointer();

      // Iterate through key data to find TSD for jemalloc
      for (var i = 0; i < BIONIC_PTHREAD_KEY_COUNT; i++) {
        const data = keyData.add(dataOff).readPointer();
        // Advance pointer to the next stage
        keyData = keyData.add(pthreadKeyDataSize);

        if (data.equals(0)) {
          continue;
        }

        const dataInfo = this.getInfo(data);

        if (dataInfo?.region) {
          // jemalloc TSD contains pointers to other structures, among them to the arena and tcache
          // check if is one of of them belong to the arena
          const ndwords = dataInfo.region.size / utils.dwordSize;
          let addr = dataInfo.region.addr;
          for (var j = 0; j < ndwords; j++) {
            const dword = addr.readPointer();
            addr = addr.add(utils.dwordSize);

            if (this.arenasAddr.some(x => x.equals(dword))) {
              tcacheArena = dword;
              tsdDwords = utils.readPointers(dataInfo.region.addr, ndwords);
              break;
            }
          }

          if (tsdDwords) {
            break;
          }
        }
      }

      if (tsdDwords === undefined) {
        // This thread does not have tcache yet since it was not found arena address
        this.tcaches[tid.toString()] = null;
        continue;
      }

      // We found correctly the TSD, go through each dword to find the tcache
      let tcacheAddr;
      for (var i = 0; i < tsdDwords.length; i++) {
        let dword = tsdDwords[i];
        if (tcacheAddr) {
          break;
        }

        if (this.getInfo(dword)?.region?.size === tcacheSize) {
          tcacheAddr = dword;
        }
      }

      if (tcacheAddr === undefined) {
        this.tcaches[tid.toString()] = null;
        continue;
      }

      this.tcaches[tid.toString()] = this.parseTcache(tcacheAddr, tcacheSize, tid);

      // Add the tid to the correspondingly arena
      for (var i = 0; i < this.arenas.length; i++) {
        if (tcacheArena.equals(this.arenas[i].addr)) {
          this.arenas[i].tids.push(tid);
          break;
        }
      }
    }
  }

  getInfo(addr: NativePointer): JemallocInfo {
    // Find the chunk that this addr belong
    var chunk = null;
    var run = null;
    var region = null;

    this.incCounter();

    for (let i = 0; i < this.chunks.length; i++) {
      const aux = this.chunks[i];
      if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(this.chunkSize)) < 0) {
        chunk = aux;
        break;
      }
    }

    if (chunk) {
      for (let i = 0; i < chunk.runs.length; i++) {
        const aux = chunk.runs[i];
        if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(aux.size)) < 0) {
          run = aux;
          break;
        }
      }
    }

    if (run) {
      for (let i = 0; i < run.regions.length; i++) {
        const aux = run.regions[i];
        if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(aux.size)) < 0) {
          region = aux;
          break;
        }
      }
    }

    return new JemallocInfo(region, run, chunk, addr);
  }

  sizeToBinSize(size: number) {
    const maxSmallSize = this.binInfo[this.nBins - 1].regSize;

    if (size > maxSmallSize) {
      return 0;
    }

    for (var i = 1; i < this.nBins; i++) {
      if (size >= this.binInfo[i - 1].regSize &&
        size < this.binInfo[i].regSize) {
        return this.binInfo[i].regSize;
      }
    }

    return 0;
  }

  setThreshold(refreshThreshold: number) {
    this.threshold = refreshThreshold;
  }

  private parseTcache(tcacheAddr: NativePointer, tcacheSize: number, tid: number) : Tcache {
    let tbinAddr = this.config.offsetStructMember(tcacheAddr, "tcache_t", "tbins");
    const tbinSize = this.config.sizeOf("tcache_bin_t");

    let tbins = [];
    for (var i = 0; i < this.nBins; i++) {
      const nbinSize = this.tbinInfo[i].ncachedMax * utils.dwordSize;
      const avail = this.config.offsetStructMember(tbinAddr, "tcache_bin_t", "avail").readPointer();
      const ncached = this.config.offsetStructMember(tbinAddr, "tcache_bin_t", "ncached").readU32();
      const lgFillDiv = this.config.offsetStructMember(tbinAddr, "tcache_bin_t", "lg_fill_div").readU32();
      const lowWater = this.config.offsetStructMember(tbinAddr, "tcache_bin_t", "low_water").readU32();

      const stack = utils.readPointers(avail.sub(nbinSize), this.tbinInfo[i].ncachedMax);
      tbins.push(new TcacheBin(tbinAddr, i, lowWater, lgFillDiv, ncached, avail, stack));

      tbinAddr = tbinAddr.add(tbinSize);
    }

    return new Tcache(tcacheAddr, tid, tbins);
  }

  private parseRun(hdrAddr: NativePointer, addr: NativePointer, size: number, binId: number) : Run {
    if (binId === -1) {
      // Large run insert it directly
      return new Run (hdrAddr, addr, size, binId, 0, [], []);
    }

    if (binId > this.nBins) {
      return null;
    }

    const runSize = <number><unknown>this.binInfo[binId].runSize;
    const regionSize = <number><unknown>this.binInfo[binId].regSize;
    const regOffset = this.binInfo[binId].regOff;
    const totalRegions = this.binInfo[binId].nRegs;
    const freeRegions = this.config.offsetStructMember(hdrAddr, "arena_run_t", "nfree").readU32();

    const regsMaskBits = Math.floor((totalRegions / 8) + 1);
    let regsMaskAddr = this.config.offsetStructMember(hdrAddr, "arena_run_t", "bitmap");
    const regsMask = [];

    for (let i = 0; i < regsMaskBits; i++) {
      const byte = regsMaskAddr.readU8();
      regsMaskAddr = regsMaskAddr.add(1);
      for (let j = 0; j < 8; j++) {
        if (regsMask.length >= totalRegions) {
          break;
        }
        if ((byte & (1 << j)) > 0) {
          regsMask.push(1);
        } else {
          regsMask.push(0);
        }
      }
    }

    const regions = [];
    const regAddr = addr.add(regOffset);

    for (let i = 0; i < totalRegions; i++) {
      const aux = regAddr.add(i * regionSize);
      regions.push(new Region(i, aux, regionSize, regsMask[i]));
    }

    return new Run(hdrAddr, addr, runSize, binId, freeRegions, regsMask, regions);
  }

  private incCounter() {
    this.counter++;

    if (this.counter > this.threshold) {
      this.parse();
    }
  }

}

class BinInfo {
  constructor(public regSize: number,
    public runSize: number,
    public regOff: number,
    public nRegs: number) {}
}

class TBinInfo {
  constructor(public ncachedMax: number) {}
}

class Chunk {
  constructor(public addr: NativePointer,
    public arenaAddr: NativePointer,
    public runs: Run[],
    public size: number) {}
}

class Region {
  constructor(public index: number,
    public addr: NativePointer,
    public size: number,
    public isFree: boolean) {}
}

class Run {
  constructor(public hdrAddr: NativePointer,
    public addr: NativePointer,
    public size: number,
    public binId: number,
    public nFree: number,
    public bitMap: number[],
    public regions: Region[]) {}
}

class ArenaBin {
  constructor(public addr: NativePointer,
    public index: number,
    public runCur?: Run) {}
}

class Arena {
  constructor(public addr: NativePointer,
    public binAddr: NativePointer,
    public index: number,
    public bins: ArenaBin[],
    public chunks: Chunk[],
    public tids: number[]) {}
}

class TcacheBin {
  constructor(public addr: NativePointer,
    public index: number,
    public lowWater: number,
    public lgFillDiv: number,
    public nCached: number,
    public avail: NativePointer,
    public stack: NativePointer[]) {}
}

class Tcache {
  constructor(public addr: NativePointer,
    public tid: number,
    public tbins: TcacheBin []) {}
}
