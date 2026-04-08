enum SupportedChain {
  bitcoin,
  bitcoinSegwit,
  dogecoin,
  eth,
  bnb,
  tron,
  xrpl,
  xrpEvm,
  solana,
  sui,
}

class SupportedChainInfo {
  const SupportedChainInfo({
    required this.chain,
    required this.chainId,
    required this.path,
  });

  final SupportedChain chain;
  final int chainId;
  final String path;
}

const Map<SupportedChain, SupportedChainInfo> supportedChainInfo = {
  SupportedChain.bitcoin: SupportedChainInfo(
    chain: SupportedChain.bitcoin,
    chainId: 0,
    path: "m/44'/0'/0'/0/0",
  ),
  SupportedChain.bitcoinSegwit: SupportedChainInfo(
    chain: SupportedChain.bitcoinSegwit,
    chainId: 0,
    path: "m/84'/0'/0'/0/0",
  ),
  SupportedChain.dogecoin: SupportedChainInfo(
    chain: SupportedChain.dogecoin,
    chainId: 3,
    path: "m/44'/3'/0'/0/0",
  ),
  SupportedChain.eth: SupportedChainInfo(
    chain: SupportedChain.eth,
    chainId: 60,
    path: "m/44'/60'/0'/0/0",
  ),
  SupportedChain.bnb: SupportedChainInfo(
    chain: SupportedChain.bnb,
    chainId: 60,
    path: "m/44'/60'/0'/0/0",
  ),
  SupportedChain.tron: SupportedChainInfo(
    chain: SupportedChain.tron,
    chainId: 195,
    path: "m/44'/195'/0'/0/0",
  ),
  SupportedChain.xrpl: SupportedChainInfo(
    chain: SupportedChain.xrpl,
    chainId: 144,
    path: "m/44'/144'/0'/0/0",
  ),
  SupportedChain.xrpEvm: SupportedChainInfo(
    chain: SupportedChain.xrpEvm,
    chainId: 60,
    path: "m/44'/60'/0'/0/0",
  ),
  SupportedChain.solana: SupportedChainInfo(
    chain: SupportedChain.solana,
    chainId: 501,
    path: "m/44'/501'/0'/0'",
  ),
  SupportedChain.sui: SupportedChainInfo(
    chain: SupportedChain.sui,
    chainId: 784,
    path: "m/44'/784'/0'/0'/0'",
  ),
};

const Map<int, SupportedChain> _defaultChainById = {
  0: SupportedChain.bitcoin,
  3: SupportedChain.dogecoin,
  60: SupportedChain.eth,
  144: SupportedChain.xrpl,
  195: SupportedChain.tron,
  501: SupportedChain.solana,
  784: SupportedChain.sui,
};

extension SupportedChainX on SupportedChain {
  int get chainId => supportedChainInfo[this]!.chainId;

  String get defaultPath => supportedChainInfo[this]!.path;

  bool get isEvm =>
      this == SupportedChain.eth ||
      this == SupportedChain.bnb ||
      this == SupportedChain.xrpEvm;

  static SupportedChain? fromChainId(int chainId) => _defaultChainById[chainId];

  static List<SupportedChain> allForChainId(int chainId) {
    return supportedChainInfo.values
        .where((info) => info.chainId == chainId)
        .map((info) => info.chain)
        .toList(growable: false);
  }
}
