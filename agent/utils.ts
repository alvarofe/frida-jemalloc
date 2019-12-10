const symbols : ISymbols = {};

export const dword_size = Process.pointerSize;
export const int_size = 4;
export const arch = Process.arch;

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

export function calculateNBins() {
  var nbins = addressSymbols(["nbins"]);
  if (nbins.equals(0)) {
    const ntbins = addressSymbols(["ntbins"]);
    const nsbins = addressSymbols(["nsbins"]);
    const nqbins = addressSymbols(["nqbins"]);

    if (ntbins.equals(0) || nsbins.equals(0) || nqbins.equals(0)) {
      if (dword_size == 8) {
        return 36;
      } else if (dword_size == 4) {
        return 39;
      }
    }

    return ntbins.readU64().add(nsbins.readU64()).add(nqbins.readU64());
  }

  return nbins.readU64();
}

