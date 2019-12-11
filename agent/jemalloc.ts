import * as utils from  "./utils";
import * as cfg from "./config";

interface IRuns {
  [addr: string] : Run;
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
  public runs = [];

  constructor(addr: NativePointer, arena_addr: NativePointer, runs: []) {
    this.addr = addr;
    this.arena_addr = arena_addr;
    this.runs = runs;
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

export class Jemalloc {
  nbins: number;
  android: cfg.BaseConfigAndroid;
  bin_info: BinInfo[] = [];
  chunks: Chunk[] = [];
  runs: IRuns = {};
  arenas_addr: NativePointer[] = [];
  narenas: number;
  chunk_size: number;

  constructor(config : cfg.BaseConfigAndroid) {
    this.android = config;
    this.nbins = <number> utils.calculateNBins();

    const arenas_arr_addr = utils.addressSymbols(['arenas', 'je_arenas']).readPointer();
    this.narenas = utils.addressSymbols(['narenas', 'narenas_total','je_narenas_total']).readU32();

    this.arenas_addr = utils.readPointers(arenas_arr_addr, this.narenas);
    this.chunk_size = utils.addressSymbols(['chunksize', 'je_chunksize']).readU32();
  }

  parse_all() {
    this.parse_bin_info();
    this.parse_chunks();
    this.parse_all_runs();
  }

  parse_bin_info() {
    console.log("[*] Parsing arena_bin_info array");
    let info_addr = utils.addressSymbols(["je_arena_bin_info"]);
    const info_size = this.android.sizeof("arena_bin_info_t");


    for (var i = 0; i < this.nbins; i++) {
      const reg_size = this.android.offsetStructMember(info_addr, "arena_bin_info_t", "reg_size").readU64();
      const run_size = this.android.offsetStructMember(info_addr, "arena_bin_info_t", "run_size").readU64();
      const reg0_off = this.android.offsetStructMember(info_addr, "arena_bin_info_t", "reg0_offset").readU32();
      const nregs = this.android.offsetStructMember(info_addr, "arena_bin_info_t", "nregs").readU32();

      this.bin_info.push(new BinInfo (reg_size, run_size, reg0_off, nregs));

      info_addr = info_addr.add(info_size);
    }
  }

  parse_chunks() {
    console.log("[*] Parsing chunks");
    const chunks_rtree_addr = utils.addressSymbols(["je_chunks_rtree"]);
    const max_height = this.android.offsetStructMember(chunks_rtree_addr, "rtree_t", "height").readU32();
    const levels_addr = chunks_rtree_addr.add(this.android.offsetof("rtree_t", "levels"));
    const rtree_levels_size = this.android.sizeof("rtree_level_t");
    let root;
    let stack = [];

    let lvl_addr = levels_addr;
    for (var i = 0; i < max_height; i++) {
      const addr = this.android.offsetStructMember(lvl_addr, "rtree_level_t", "subtree").readPointer();
      if (addr.equals(0)) {
        lvl_addr = lvl_addr.add(rtree_levels_size);
        continue;
      }

      root = [addr, i];
      break;
    }

    stack.push(root);

    while (stack.length > 0) {
      let element = stack.pop();
      let node = element[0];
      const height = element[1];

      const cur_level_addr = levels_addr.add(height * rtree_levels_size);
      const bits = cur_level_addr.add(this.android.offsetof("rtree_level_t", "bits")).readU32();
      const max_key = 1 << bits;

      for (let i = 0; i < max_key; i++) {
        const addr = node.readPointer();
        node = node.add(8);

        if (addr.equals(0))
          continue;

        if (height === max_height - 1) {
          const node_addr = addr.add(this.android.offsetof("arena_chunk_t", "node"));
          const arena_addr = node_addr.add(this.android.offsetof("extent_node_t", "en_arena")).readPointer();

          if (<number><unknown> addr & 0xfff) {
            continue;
          }

          if (this.arenas_addr.some(x => x.equals(arena_addr))) {
            this.chunks.push(new Chunk(addr, arena_addr, []));
          } else {
            this.chunks.push(new Chunk(addr, ptr(0), []));
          }
        } else {
          stack.push([addr, height + 1]);
        }
      }
    }
  }

  parse_all_runs() {
    console.log("[*] Parsing all runs");

    const map_bias = utils.addressSymbols(["je_map_bias"]).readU32();
    const chunk_npages = this.chunk_size >> 12;
    const chunk_map_dwords = Math.floor(this.android.sizeof("arena_chunk_map_bits_t") / utils.dword_size);
    const bitmap_count = (chunk_npages - map_bias) * chunk_map_dwords;
    const map_misc_offset = utils.addressSymbols(["je_map_misc_offset"]).readU64();
    const map_misc_size = this.android.sizeof("arena_chunk_map_misc_t")
    const run_off = this.android.offsetof("arena_chunk_map_misc_t", "run");
    // the 12 least significant bits of each bitmap entry hold
    // various flags for the corresponding run
    const flags_mask = (1 << 12) - 1;

    for (var i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];

      if (chunk.arena_addr.equals(0))
        continue;

      const node_off = this.android.offsetof("arena_chunk_t", "node");
      const en_addr_off = this.android.offsetof("extent_node_t", "en_addr");
      const en_addr = chunk.addr.add(node_off).add(en_addr_off).readPointer();

      if (!en_addr.equals(chunk.addr)) {
        continue;
      }

      const bitmap_addr = this.android.offsetStructMember(chunk.addr, "arena_chunk_t", "map_bits");
      const bitmap = utils.readPointers(bitmap_addr, bitmap_count);

      for (var j = 0; j < bitmap.length; j++) {
        const mapelm = <number><unknown> bitmap[j];
        let bin_size;
        let binid;

        if ((mapelm & 0xf) === 1) {
          // Small allocation
          let offset;
          if (this.android.version === "6") {
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
          if (this.android.version === "6") {
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
    if (hdr_addr.equals(0) || size === 0) {
      return;
    }

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
    const free_regions = this.android.offsetStructMember(hdr_addr, "arena_run_t", "nfree").readU32();

    const regs_mask_bits = Math.floor((total_regions / 8) + 1);
    let regs_mask_addr = this.android.offsetStructMember(hdr_addr, "arena_run_t", "bitmap");
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
