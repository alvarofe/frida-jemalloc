import * as utils from  "./utils";
import * as android from "./android";

interface IRuns {
  [addr: string] : Run;
}

export class JemallocInfo {
  public region: Region;
  public run: Run;
  public chunk: Chunk;
  public addr: NativePointer;

  constructor(region: Region, run: Run, chunk: Chunk, addr: NativePointer) {
    this.region = region;
    this.run = run;
    this.chunk = chunk;
    this.addr = addr;
  }

  dump() {
    console.log("[*] Jemalloc info of " + this.addr);
    if (this.chunk !== null) {
      console.log(" Chunk:");
      console.log("  Address : " + this.chunk.addr);
      console.log("  Size    : 0x" + this.chunk.size.toString(16));
    }
    if (this.run !== null) {
      console.log(" Run:");
      console.log("  Address : " + this.run.addr);
      console.log("  Size    : 0x" + this.run.size.toString(16));
    }
    if (this.region !== null) {
      console.log(" Region:");
      console.log("  Address : " + this.region.addr);
      console.log("  Size    : 0x" + this.region.size.toString(16));
    }
  }
}

export class Jemalloc {
  public nbins: number;
  config: android.BaseConfigAndroid;
  public bin_info: BinInfo[] = [];
  public chunks: Chunk[] = [];
  public runs: IRuns = {};
  arenas_addr: NativePointer[] = [];
  narenas: number;
  chunk_size: number;
  threshold: number = 0;
  counter: number;

  constructor() {
    utils.collectSymbols();
    this.config = android.getAndroidConfig();
    if (this.config === null) {
      console.log("[-] frida-jemalloc could not detect android config");
      return;
    }

    this.nbins = <number> utils.calculateNBins();

    const arenas_arr_addr = utils.addressSymbols(['arenas', 'je_arenas']).readPointer();
    this.narenas = utils.addressSymbols(['narenas', 'narenas_total','je_narenas_total']).readU32();

    this.arenas_addr = utils.readPointers(arenas_arr_addr, this.narenas);
    this.chunk_size = utils.addressSymbols(['chunksize', 'je_chunksize']).readU32();
  }

  set_threshold(refresh_threshold: number) {
    this.threshold = refresh_threshold;
  }

  inc_counter() {
    this.counter += 1;

    if (this.counter > this.threshold) {
      this.counter = 0;
      this.parse_all;
    }
  }

  get_info(addr: NativePointer): JemallocInfo {
    // Find the chunk that this addr belong
    var chunk = null;
    var run = null;
    var region = null;

    this.inc_counter();

    for (let i = 0; i < this.chunks.length; i++) {
      const aux = this.chunks[i];
      if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(this.chunk_size)) < 0) {
        chunk = aux;
        break;
      }
    }

    for (let i = 0; i < chunk.runs.length; i++) {
      const aux = chunk.runs[i];
      if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(aux.size)) < 0) {
        run = aux;
        break;
      }
    }

    for (let i = 0; i < run.regions.length; i++) {
      const aux = run.regions[i];
      if (addr.compare(aux.addr) >= 0 &&
          addr.compare(aux.addr.add(aux.size)) < 0) {
        region = aux;
        break;
      }
    }

    return new JemallocInfo(region, run, chunk, addr);
  }

  parse_all() {
    if (this.config !== null) {
      this.parse_bin_info();
      this.parse_chunks();
      this.parse_all_runs();
    }
  }

  parse_bin_info() {
    let info_addr = utils.addressSymbols(["je_arena_bin_info"]);
    const info_size = this.config.sizeof("arena_bin_info_t");

    this.bin_info = [];

    for (var i = 0; i < this.nbins; i++) {
      const reg_size = this.config.offsetStructMember(info_addr, "arena_bin_info_t", "reg_size").readU64();
      const run_size = this.config.offsetStructMember(info_addr, "arena_bin_info_t", "run_size").readU64();
      const reg0_off = this.config.offsetStructMember(info_addr, "arena_bin_info_t", "reg0_offset").readU32();
      const nregs = this.config.offsetStructMember(info_addr, "arena_bin_info_t", "nregs").readU32();

      this.bin_info.push(new BinInfo (reg_size, run_size, reg0_off, nregs));

      info_addr = info_addr.add(info_size);
    }
  }

  parse_chunks() {
    const chunks_rtree_addr = utils.addressSymbols(["je_chunks_rtree"]);
    const max_height = this.config.offsetStructMember(chunks_rtree_addr, "rtree_t", "height").readU32();
    const levels_addr = chunks_rtree_addr.add(this.config.offsetof("rtree_t", "levels"));
    const rtree_levels_size = this.config.sizeof("rtree_level_t");
    let root;
    let stack = [];

    let lvl_addr = levels_addr;
    for (var i = 0; i < max_height; i++) {
      const addr = this.config.offsetStructMember(lvl_addr, "rtree_level_t", "subtree").readPointer();
      if (addr.equals(0)) {
        lvl_addr = lvl_addr.add(rtree_levels_size);
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

      const cur_level_addr = levels_addr.add(height * rtree_levels_size);
      const bits = cur_level_addr.add(this.config.offsetof("rtree_level_t", "bits")).readU32();
      const max_key = 1 << bits;

      for (let i = 0; i < max_key; i++) {
        const addr = node.readPointer();
        node = node.add(8);

        if (addr.equals(0))
          continue;

        if (height === max_height - 1) {
          const node_addr = addr.add(this.config.offsetof("arena_chunk_t", "node"));
          const arena_addr = node_addr.add(this.config.offsetof("extent_node_t", "en_arena")).readPointer();

          if (<number><unknown> addr & 0xfff) {
            continue;
          }

          if (this.arenas_addr.some(x => x.equals(arena_addr))) {
            this.chunks.push(new Chunk(addr, arena_addr, [], this.chunk_size));
          } else {
            this.chunks.push(new Chunk(addr, ptr(0), [], this.chunk_size));
          }
        } else {
          stack.push([addr, height + 1]);
        }
      }
    }
  }

  parse_all_runs() {
    const map_bias = utils.addressSymbols(["je_map_bias"]).readU32();
    const chunk_npages = this.chunk_size >> 12;
    const chunk_map_dwords = Math.floor(this.config.sizeof("arena_chunk_map_bits_t") / utils.dword_size);
    const bitmap_count = (chunk_npages - map_bias) * chunk_map_dwords;
    const map_misc_offset = utils.addressSymbols(["je_map_misc_offset"]).readU64();
    const map_misc_size = this.config.sizeof("arena_chunk_map_misc_t")
    const run_off = this.config.offsetof("arena_chunk_map_misc_t", "run");
    // the 12 least significant bits of each bitmap entry hold
    // various flags for the corresponding run
    const flags_mask = (1 << 12) - 1;

    this.runs = {};

    for (var i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];

      if (chunk.arena_addr.equals(0))
        continue;

      const node_off = this.config.offsetof("arena_chunk_t", "node");
      const en_addr_off = this.config.offsetof("extent_node_t", "en_addr");
      const en_addr = chunk.addr.add(node_off).add(en_addr_off).readPointer();

      if (!en_addr.equals(chunk.addr)) {
        continue;
      }

      const bitmap_addr = this.config.offsetStructMember(chunk.addr, "arena_chunk_t", "map_bits");
      const bitmap = utils.readPointers(bitmap_addr, bitmap_count);

      for (var j = 0; j < bitmap.length; j++) {
        const mapelm = <number><unknown> bitmap[j];
        let bin_size;
        let binid;

        if ((mapelm & 0xf) === 1) {
          // Small allocation
          let offset;
          if (this.config.version === "6") {
            offset = mapelm & ~flags_mask;
            binid = (mapelm & 0xff0) >> 4;
          } else {
            offset = (mapelm & ~0x1fff) >> 1;
            binid = (mapelm & 0x1fe0) >> 5;
          }

          bin_size = this.bin_info[binid].run_size;
          // part of the previous run
          if (offset != 0 || bin_size.equals(0)) {
            continue;
          }

        } else if ((mapelm & 0xf) === 3) {
          // Large allocations
          if (this.config.version === "6") {
            bin_size = mapelm & ~flags_mask;
          } else {
            bin_size = (mapelm & ~0x1fff) >> 1;
          }

          if (bin_size === 0) {
            continue;
          }
          binid = -1;

        } else {
          continue;
        }

        const map_misc_addr = chunk.addr.add(map_misc_offset);
        const cur_arena_chunk_map_misc = map_misc_addr.add(j * map_misc_size);
        const hdr_addr = cur_arena_chunk_map_misc.add(run_off);
        const addr = chunk.addr.add((j + map_bias) * utils.page_size);

        if (hdr_addr.equals(0)) {
          continue;
        }

        const run = this.parse_run(hdr_addr, addr, bin_size, binid);

        if (run !== null) {
          this.runs[hdr_addr.toString()] = run;
          chunk.runs.push(run);
        }
      }
    }
  }

  parse_run(hdr_addr: NativePointer, addr: NativePointer, size: number, binid: number) : Run {
    if (binid === -1) {
      // Large run insert it directly
      return new Run (hdr_addr, addr, size, binid, 0, [], []);
    }

    if (binid > this.nbins) {
      return null;
    }

    const run_size = <number><unknown>this.bin_info[binid].run_size;
    const region_size = <number><unknown>this.bin_info[binid].reg_size;
    const reg0_offset = this.bin_info[binid].reg0_off;
    const total_regions = this.bin_info[binid].nregs;
    const free_regions = this.config.offsetStructMember(hdr_addr, "arena_run_t", "nfree").readU32();

    const regs_mask_bits = Math.floor((total_regions / 8) + 1);
    let regs_mask_addr = this.config.offsetStructMember(hdr_addr, "arena_run_t", "bitmap");
    const regs_mask = [];

    for (let i = 0; i < regs_mask_bits; i++) {
      const byte = regs_mask_addr.readU8();
      regs_mask_addr = regs_mask_addr.add(1);
      for (let j = 0; j < 8; j++) {
        if (regs_mask.length >= total_regions) {
          break;
        }
        if ((byte & (1 << j)) > 0) {
          regs_mask.push(1);
        } else {
          regs_mask.push(0);
        }
      }
    }

    const regions = [];
    const reg0_addr = addr.add(reg0_offset);

    for (let i = 0; i < total_regions; i++) {
      const reg_addr = reg0_addr.add(i * region_size);
      regions.push(new Region(i, reg_addr, region_size, regs_mask[i]));
    }

    return new Run(hdr_addr, addr, run_size, binid, free_regions, regs_mask, regions);
  }
}

class BinInfo {
  public reg_size: UInt64;
  public run_size: UInt64;
  public reg0_off: number;
  public nregs: number;

  constructor(reg_size: UInt64, run_size: UInt64, reg0_off: number, nregs: number) {
    this.reg_size = reg_size;
    this.run_size = run_size;
    this.reg0_off = reg0_off;
    this.nregs = nregs;
  }
}

class Chunk {
  public addr: NativePointer;
  public arena_addr: NativePointer;
  public runs : Run[] = [];
  public size: number;

  constructor(addr: NativePointer, arena_addr: NativePointer, runs: Run[], size: number) {
    this.addr = addr;
    this.arena_addr = arena_addr;
    this.runs = runs;
    this.size = size;
  }
}

class Region {
  public index: number;
  public addr: NativePointer;
  public size: number;
  public is_free: boolean;

  constructor(index: number, addr: NativePointer, size: number, is_free: boolean) {
    this.index = index;
    this.addr = addr;
    this.size = size;
    this.is_free = is_free;
  }
}

class Run {
  public hdr_addr: NativePointer;
  public addr: NativePointer;
  public size: number;
  public binid: number;
  public nfree: number;
  public bitmap: number[];
  public regions: Region[];

  constructor(hdr_addr: NativePointer, addr: NativePointer, size: number, binid: number, nfree: number, bitmap: number[], regions: Region[]) {
    this.hdr_addr = hdr_addr;
    this.addr = addr;
    this.size = size;
    this.binid = binid;
    this.nfree = nfree;
    this.bitmap = bitmap;
    this.regions = regions;
  }
}

