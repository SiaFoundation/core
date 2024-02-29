package rhp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

const (
	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB
	// SegmentSize is the size of one segment in bytes.
	SegmentSize = 64
)

func round4KiB(n uint64) uint64 {
	return (n + (1<<12 - 1)) &^ (1<<12 - 1)
}

// A Transport is a pair of protocol and address that a host may be reached on.
type Transport struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

// HostPrices specify a time-bound set of parameters used to calculate the cost
// of various RPCs.
type HostPrices struct {
	ContractPrice types.Currency `json:"contractPrice"`
	Collateral    types.Currency `json:"collateral"`
	StoragePrice  types.Currency `json:"storagePrice"`
	IngressPrice  types.Currency `json:"ingressPrice"`
	EgressPrice   types.Currency `json:"egressPrice"`
	TipHeight     uint64         `json:"tipHeight"`
	ValidUntil    time.Time      `json:"validUntil"`

	// covers above fields
	Signature types.Signature `json:"signature"`
}

func (hp HostPrices) ReadSectorCost(length uint64) types.Currency {
	return hp.EgressPrice.Mul64(round4KiB(length))
}

func (hp HostPrices) WriteSectorCost(sector []byte) types.Currency {
	return hp.IngressPrice.Mul64(round4KiB(uint64(len(sector))))
}

// HostSettings specify the settings of a host.
type HostSettings struct {
	ProtocolVersion    [3]uint8       `json:"protocolVersion"`
	Release            string         `json:"release"`
	Transports         []Transport    `json:"transports"`
	WalletAddress      types.Address  `json:"walletAddress"`
	AcceptingContracts bool           `json:"acceptingContracts"`
	MaxCollateral      types.Currency `json:"maxCollateral"`
	MaxDuration        uint64         `json:"maxDuration"`
	RemainingStorage   uint64         `json:"remainingStorage"`
	TotalStorage       uint64         `json:"totalStorage"`
	Prices             HostPrices     `json:"prices"`
}

// Sign signs the host prices with the given key.
func (hs *HostSettings) Sign(sk types.PrivateKey) {
	// NOTE: this is a method on HostSettings (rather than HostPrices itself)
	// because that gives us access to the protocol version.
	h := types.NewHasher()
	hs.Prices.Signature = types.Signature{}
	hs.Prices.EncodeTo(h.E)
	hs.Prices.Signature = sk.SignHash(h.Sum())
}

// A WriteAction adds or modifies sectors within a contract.
type WriteAction struct {
	Type uint8         `json:"type"`
	Root types.Hash256 `json:"root,omitempty"` // Append
	A    uint64        `json:"a,omitempty"`    // Swap
	B    uint64        `json:"b,omitempty"`    // Swap
	N    uint64        `json:"n,omitempty"`    // Trim
}

// WriteAction types.
const (
	ActionAppend = iota + 1
	ActionSwap
	ActionTrim
	ActionUpdate // TODO: implement
)

// An Account represents an ephemeral balance that can be funded via contract
// revision and spent to pay for RPCs.
type Account types.PublicKey

// String implements fmt.Stringer.
func (a Account) String() string { return fmt.Sprintf("acct:%x", a[:]) }

// MarshalText implements encoding.TextMarshaler.
func (a Account) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Account) UnmarshalText(b []byte) error {
	n, err := hex.Decode(a[:], bytes.TrimPrefix(b, []byte("acct:")))
	if err != nil {
		return fmt.Errorf("decoding acct:<hex> failed: %w", err)
	} else if n < len(a) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// An AccountToken authorizes an account action.
type AccountToken struct {
	Account    Account         `json:"account"`
	ValidUntil time.Time       `json:"validUntil"`
	Signature  types.Signature `json:"signature"`
}

func (at *AccountToken) sigHash() types.Hash256 {
	h := types.NewHasher()
	at.Account.EncodeTo(h.E)
	h.E.WriteTime(at.ValidUntil)
	return h.Sum()
}

// Sign signs the account token with the given key.
func (at *AccountToken) Sign(sk types.PrivateKey) {
	at.Signature = sk.SignHash(at.sigHash())
}

// Verify verifies the account token.
func (at AccountToken) Verify() bool {
	return types.PublicKey(at.Account).VerifyHash(at.sigHash(), at.Signature)
}

// GenerateAccount generates a pair of private key and Account from a secure
// entropy source.
func GenerateAccount() (types.PrivateKey, Account) {
	sk := types.GeneratePrivateKey()
	return sk, Account(sk.PublicKey())
}

type (
	// RPCSettingsRequest implements Request.
	RPCSettingsRequest struct{}

	// RPCSettingsResponse implements Object.
	RPCSettingsResponse struct {
		Settings HostSettings `json:"settings"`
	}

	// RPCFormContractRequest implements Request.
	RPCFormContractRequest struct {
		Prices        HostPrices             `json:"prices"`
		Contract      types.V2FileContract   `json:"contract"`
		RenterInputs  []types.V2SiacoinInput `json:"renterInputs"`
		RenterParents []types.V2Transaction  `json:"renterParents"`
	}
	// RPCFormContractResponse implements Object.
	RPCFormContractResponse struct {
		HostInputs  []types.V2SiacoinInput `json:"hostInputs"`
		HostParents []types.V2Transaction  `json:"hostParents"`
	}
	// RPCFormContractSecondResponse implements Object.
	RPCFormContractSecondResponse struct {
		RenterContractSignature types.Signature         `json:"renterContractSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}
	// RPCFormContractThirdResponse implements Object.
	RPCFormContractThirdResponse struct {
		HostContractSignature types.Signature         `json:"hostContractSignature"`
		HostSatisfiedPolicies []types.SatisfiedPolicy `json:"hostSatisfiedPolicies"`
	}

	// RPCRenewContractRequest implements Request.
	RPCRenewContractRequest struct {
		Prices        HostPrices                     `json:"prices"`
		Renewal       types.V2FileContractResolution `json:"renewal"`
		RenterInputs  []types.V2SiacoinInput         `json:"renterInputs"`
		RenterParents []types.V2Transaction          `json:"renterParents"`
	}
	// RPCRenewContractResponse implements Object.
	RPCRenewContractResponse struct {
		HostInputs  []types.V2SiacoinInput `json:"hostInputs"`
		HostParents []types.V2Transaction  `json:"hostParents"`
	}
	// RPCRenewContractSecondResponse implements Object.
	RPCRenewContractSecondResponse struct {
		RenterContractSignature types.Signature         `json:"renterContractSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}
	// RPCRenewContractThirdResponse implements Object.
	RPCRenewContractThirdResponse struct {
		HostContractSignature types.Signature         `json:"hostContractSignature"`
		HostSatisfiedPolicies []types.SatisfiedPolicy `json:"hostSatisfiedPolicies"`
	}

	// RPCModifySectorsRequest implements Request.
	RPCModifySectorsRequest struct {
		Prices  HostPrices    `json:"prices"`
		Actions []WriteAction `json:"actions"`
	}
	// RPCModifySectorsResponse implements Object.
	RPCModifySectorsResponse struct {
		Proof []types.Hash256 `json:"proof"`
	}
	// RPCModifySectorsSecondResponse implements Object.
	RPCModifySectorsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCModifySectorsThirdResponse implements Object.
	RPCModifySectorsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCLatestRevisionRequest implements Request.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID `json:"contractID"`
	}
	// RPCLatestRevisionResponse implements Object.
	RPCLatestRevisionResponse struct {
		Contract types.V2FileContract `json:"contract"`
	}

	// RPCReadSectorRequest implements Request.
	RPCReadSectorRequest struct {
		Prices HostPrices    `json:"prices"`
		Token  AccountToken  `json:"token"`
		Root   types.Hash256 `json:"root"`
		Offset uint64        `json:"offset"`
		Length uint64        `json:"length"`
	}
	// RPCReadSectorResponse implements Object.
	RPCReadSectorResponse struct {
		Proof  []types.Hash256 `json:"proof"`
		Sector []byte          `json:"sector"`
	}

	// RPCWriteSectorRequest implements Request.
	RPCWriteSectorRequest struct {
		Prices HostPrices   `json:"prices"`
		Token  AccountToken `json:"token"`
		Sector []byte       `json:"sector"` // extended to SectorSize by host
	}
	// RPCWriteSectorResponse implements Object.
	RPCWriteSectorResponse struct {
		Root types.Hash256 `json:"root"`
	}

	// RPCSectorRootsRequest implements Request.
	RPCSectorRootsRequest struct {
		Prices          HostPrices           `json:"prices"`
		ContractID      types.FileContractID `json:"contractID"`
		RenterSignature types.Signature      `json:"renterSignature"`
		Offset          uint64               `json:"offset"`
		Length          uint64               `json:"length"`
	}
	// RPCSectorRootsResponse implements Object.
	RPCSectorRootsResponse struct {
		Proof         []types.Hash256 `json:"proof"`
		Roots         []types.Hash256 `json:"roots"`
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCAccountBalanceRequest implements Request.
	RPCAccountBalanceRequest struct {
		Account Account `json:"account"`
	}
	// RPCAccountBalanceResponse implements Object.
	RPCAccountBalanceResponse struct {
		Balance types.Currency `json:"balance"`
	}

	// An AccountDeposit represents a transfer into an account.
	AccountDeposit struct {
		Account Account        `json:"account"`
		Amount  types.Currency `json:"amount"`
	}

	// RPCFundAccountRequest implements Request.
	RPCFundAccountRequest struct {
		ContractID      types.FileContractID `json:"contractID"`
		Deposits        []AccountDeposit     `json:"deposits"`
		RenterSignature types.Signature      `json:"renterSignature"`
	}
	// RPCFundAccountResponse implements Object.
	RPCFundAccountResponse struct {
		Balances      []types.Currency `json:"balances"`
		HostSignature types.Signature  `json:"hostSignature"`
	}
)

// A Request is the initial request object for an RPC.
type Request interface {
	Object
	ID() types.Specifier
}

// ID implements Request.
func (RPCAccountBalanceRequest) ID() types.Specifier { return types.NewSpecifier("AccountBalance") }

// ID implements Request.
func (RPCFormContractRequest) ID() types.Specifier { return types.NewSpecifier("FormContract") }

// ID implements Request.
func (RPCFundAccountRequest) ID() types.Specifier { return types.NewSpecifier("FundAccount") }

// ID implements Request.
func (RPCLatestRevisionRequest) ID() types.Specifier { return types.NewSpecifier("LatestRevision") }

// ID implements Request.
func (RPCModifySectorsRequest) ID() types.Specifier { return types.NewSpecifier("ModifySectors") }

// ID implements Request.
func (RPCReadSectorRequest) ID() types.Specifier { return types.NewSpecifier("ReadSector") }

// ID implements Request.
func (RPCRenewContractRequest) ID() types.Specifier { return types.NewSpecifier("RenewContract") }

// ID implements Request.
func (RPCSectorRootsRequest) ID() types.Specifier { return types.NewSpecifier("SectorRoots") }

// ID implements Request.
func (RPCSettingsRequest) ID() types.Specifier { return types.NewSpecifier("Settings") }

// ID implements Request.
func (RPCWriteSectorRequest) ID() types.Specifier { return types.NewSpecifier("WriteSector") }

var idMap = map[types.Specifier]func() Request{
	(RPCAccountBalanceRequest{}).ID(): func() Request { return new(RPCAccountBalanceRequest) },
	(RPCFormContractRequest{}).ID():   func() Request { return new(RPCFormContractRequest) },
	(RPCFundAccountRequest{}).ID():    func() Request { return new(RPCFundAccountRequest) },
	(RPCLatestRevisionRequest{}).ID(): func() Request { return new(RPCLatestRevisionRequest) },
	(RPCModifySectorsRequest{}).ID():  func() Request { return new(RPCModifySectorsRequest) },
	(RPCReadSectorRequest{}).ID():     func() Request { return new(RPCReadSectorRequest) },
	(RPCRenewContractRequest{}).ID():  func() Request { return new(RPCRenewContractRequest) },
	(RPCSectorRootsRequest{}).ID():    func() Request { return new(RPCSectorRootsRequest) },
	(RPCSettingsRequest{}).ID():       func() Request { return new(RPCSettingsRequest) },
	(RPCWriteSectorRequest{}).ID():    func() Request { return new(RPCWriteSectorRequest) },
}

// RequestforID returns the intial request object for a given ID, or nil if the
// ID is not recognized.
func RequestforID(id types.Specifier) Request {
	if r := idMap[id]; r != nil {
		return r()
	}
	return nil
}

func NewContract(hs HostSettings, allowance, collateral types.Currency, proofHeight uint64, renterAddress types.Address, renterPublicKey, hostPublicKey types.PublicKey) types.V2FileContract {
	const proofWindow = 144
	return types.V2FileContract{
		Filesize:         0,
		FileMerkleRoot:   types.Hash256{},
		ProofHeight:      proofHeight,
		ExpirationHeight: proofHeight + proofWindow,
		RenterOutput: types.SiacoinOutput{
			Value:   allowance,
			Address: renterAddress,
		},
		HostOutput: types.SiacoinOutput{
			Value:   collateral.Add(hs.Prices.ContractPrice),
			Address: hs.WalletAddress,
		},
		HostCollateral:  collateral,
		RenterPublicKey: renterPublicKey,
		HostPublicKey:   hostPublicKey,
		RevisionNumber:  0,
	}
}

func ContractCost(cs consensus.State, hs HostSettings, fc types.V2FileContract, minerFee types.Currency) (renter, host types.Currency) {
	return fc.RenterOutput.Value.Add(hs.Prices.ContractPrice).Add(minerFee), fc.HostOutput.Value.Sub(hs.Prices.ContractPrice)
}

func FormContractTransaction(cs consensus.State, req RPCFormContractRequest, resp RPCFormContractResponse) types.V2Transaction {
	txn := types.V2Transaction{
		FileContracts: []types.V2FileContract{req.Contract},
		MinerFee:      types.ZeroCurrency, // TODO
	}
	var renterSum types.Currency
	for _, sci := range req.RenterInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci)
		renterSum = renterSum.Add(sci.Parent.SiacoinOutput.Value)
	}
	if change := renterSum.Sub(req.Contract.RenterOutput.Value); !change.IsZero() { // TODO
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   change,
			Address: req.Contract.RenterOutput.Address,
		})
	}
	var hostSum types.Currency
	for _, sci := range resp.HostInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci)
		hostSum = hostSum.Add(sci.Parent.SiacoinOutput.Value)
	}
	if change := hostSum.Sub(req.Contract.HostOutput.Value); !change.IsZero() { // TODO
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   change,
			Address: req.Contract.HostOutput.Address,
		})
	}
	return txn
}

func SignFormContractTransaction(txn *types.V2Transaction, resp2 RPCFormContractSecondResponse, resp3 RPCFormContractThirdResponse) {
	txn.FileContracts[0].RenterSignature = resp2.RenterContractSignature
	txn.FileContracts[0].HostSignature = resp3.HostContractSignature
	for i := range txn.SiacoinInputs {
		sci := &txn.SiacoinInputs[i]
		if i < len(resp2.RenterSatisfiedPolicies) {
			sci.SatisfiedPolicy = resp2.RenterSatisfiedPolicies[i]
		} else {
			sci.SatisfiedPolicy = resp3.HostSatisfiedPolicies[i-len(resp2.RenterSatisfiedPolicies)]
		}
	}
}

func RenewContractTransaction(cs consensus.State, req RPCRenewContractRequest, resp RPCRenewContractResponse) types.V2Transaction {
	renewal := req.Renewal.Resolution.(*types.V2FileContractRenewal)
	txn := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{req.Renewal},
		MinerFee:                types.ZeroCurrency, // TODO
	}
	var renterSum types.Currency
	for _, sci := range req.RenterInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci)
		renterSum = renterSum.Add(sci.Parent.SiacoinOutput.Value)
	}
	if change := renterSum.Sub(renewal.NewContract.RenterOutput.Value); !change.IsZero() { // TODO
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   change,
			Address: renewal.NewContract.RenterOutput.Address,
		})
	}
	var hostSum types.Currency
	for _, sci := range resp.HostInputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, sci)
		hostSum = hostSum.Add(sci.Parent.SiacoinOutput.Value)
	}
	if change := hostSum.Sub(renewal.NewContract.HostOutput.Value); !change.IsZero() { // TODO
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   change,
			Address: renewal.NewContract.HostOutput.Address,
		})
	}
	return txn
}

func SignRenewContractTransaction(txn *types.V2Transaction, resp2 RPCRenewContractSecondResponse, resp3 RPCRenewContractThirdResponse) {
	txn.FileContracts[0].RenterSignature = resp2.RenterContractSignature
	txn.FileContracts[0].HostSignature = resp3.HostContractSignature
	for i := range txn.SiacoinInputs {
		sci := &txn.SiacoinInputs[i]
		if i < len(resp2.RenterSatisfiedPolicies) {
			sci.SatisfiedPolicy = resp2.RenterSatisfiedPolicies[i]
		} else {
			sci.SatisfiedPolicy = resp3.HostSatisfiedPolicies[i-len(resp2.RenterSatisfiedPolicies)]
		}
	}
}

func pay(fc types.V2FileContract, amount types.Currency) types.V2FileContract {
	if fc.RenterOutput.Value.Cmp(amount) < 0 {
		amount = fc.RenterOutput.Value
	}
	fc.RenterOutput.Value = fc.RenterOutput.Value.Sub(amount)
	fc.HostOutput.Value = fc.HostOutput.Value.Add(amount)
	return fc
}

func pledge(fc types.V2FileContract, amount types.Currency) types.V2FileContract {
	if fc.HostCollateral.Cmp(amount) < 0 {
		amount = fc.HostCollateral
	}
	fc.HostCollateral = fc.HostCollateral.Sub(amount)
	return fc
}

func ReviseForModifySectors(fc types.V2FileContract, req RPCModifySectorsRequest, resp RPCModifySectorsResponse) types.V2FileContract {
	old := fc.Filesize
	for _, action := range req.Actions {
		switch action.Type {
		case ActionAppend:
			fc.Filesize += SectorSize // NOTE: ingress cost paid via account
		case ActionTrim:
			fc.Filesize -= SectorSize * action.N
		}
	}
	if fc.Filesize > old {
		size := fc.Filesize - old
		duration := fc.ProofHeight - req.Prices.TipHeight
		fc = pay(fc, req.Prices.StoragePrice.Mul64(size).Mul64(duration))
		fc = pledge(fc, req.Prices.Collateral.Mul64(size).Mul64(duration))
	}
	fc.FileMerkleRoot = resp.Proof[len(resp.Proof)-1] // TODO
	return fc
}

func ReviseForSectorRoots(fc types.V2FileContract, prices HostPrices, numRoots uint64) types.V2FileContract {
	return pay(fc, prices.EgressPrice.Mul64(round4KiB(32*numRoots)))
}

func ReviseForFundAccount(fc types.V2FileContract, amount types.Currency) types.V2FileContract {
	return pay(fc, amount)
}
