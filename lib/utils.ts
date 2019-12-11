const symbols : ISymbols = {};

export const dwordSize = Process.pointerSize;
export const pageSize = Process.pageSize;

interface ISymbols {
  [name: string] : ModuleSymbolDetails;
}

export function collectSymbols() {
  Process.getModuleByName("libc.so").enumerateSymbols().forEach(function (symbol) {
    symbols[symbol.name] = symbol;
  });
}

export function addressSymbols(names: string[]) : NativePointer {
  for (var i = 0; i < names.length; i++) {
    if (names[i] in symbols) {
      return symbols[names[i]].address;
    }
  }

  return ptr(0);
}

export function readPointers(addr: NativePointer, amount: number) : NativePointer[] {
  const pointers: NativePointer[] = [];

  for (var i = 0; i < amount; i++) {
    pointers.push(addr.readPointer());
    addr = addr.add(dwordSize);
  }

  return pointers;
}

export function calculateNBins() {
  var nBins = addressSymbols(["nbins"]);
  if (nBins.equals(0)) {
    const nTbins = addressSymbols(["ntbins"]);
    const nSbins = addressSymbols(["nsbins"]);
    const nQbins = addressSymbols(["nqbins"]);

    if (nTbins.equals(0) || nSbins.equals(0) || nQbins.equals(0)) {
      if (dwordSize == 8) {
        return 36;
      } else if (dwordSize == 4) {
        return 39;
      }
    }

    return nTbins.readU64().add(nSbins.readU64()).add(nQbins.readU64());
  }

  return nBins.readU64();
}

