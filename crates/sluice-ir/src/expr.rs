//! Normalized expression model.
//!
//! Decoupled from `solang_parser` so that downstream passes never depend on the
//! parser. The interesting design choice — mirroring how `vortex-ir` classifies
//! opcodes — is that **calls are pre-classified** ([`CallKind`]) and known
//! builtins are recognized ([`Builtin`]) at parse time, and value origins are
//! labelled with [`ValueSource`]. This means a detector can ask "is this an
//! external low-level call?" or "is this a price-like read?" straight from the
//! IR, without re-deriving it.

use crate::ids::Span;
use serde::{Deserialize, Serialize};

/// An expression node carrying its source location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Expr {
    pub span: Span,
    pub kind: ExprKind,
}

impl Expr {
    pub fn new(span: Span, kind: ExprKind) -> Self {
        Self { span, kind }
    }

    pub fn dummy(kind: ExprKind) -> Self {
        Self { span: Span::dummy(), kind }
    }

    /// If this expression is a call, return it.
    pub fn as_call(&self) -> Option<&Call> {
        match &self.kind {
            ExprKind::Call(c) => Some(c),
            _ => None,
        }
    }

    /// Resolve a simple textual name if this expression is an identifier or a
    /// member access (`a.b` -> `"b"`). Best-effort, used for heuristics.
    pub fn simple_name(&self) -> Option<&str> {
        match &self.kind {
            ExprKind::Ident(n) => Some(n),
            ExprKind::Member { member, .. } => Some(member),
            _ => None,
        }
    }

    /// True if this expression mentions `msg.sender` anywhere shallowly.
    pub fn mentions_member(&self, base: &str, member: &str) -> bool {
        if let ExprKind::Member { base: b, member: m } = &self.kind {
            if m == member {
                if let ExprKind::Ident(n) = &b.kind {
                    if n == base {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Walk this expression and all sub-expressions, invoking `f` on each.
    pub fn visit<'a>(&'a self, f: &mut impl FnMut(&'a Expr)) {
        f(self);
        match &self.kind {
            ExprKind::Member { base, .. } => base.visit(f),
            ExprKind::Index { base, index } => {
                base.visit(f);
                if let Some(i) = index {
                    i.visit(f);
                }
            }
            ExprKind::Call(c) => {
                c.callee.visit(f);
                if let Some(r) = &c.receiver {
                    r.visit(f);
                }
                if let Some(v) = &c.value {
                    v.visit(f);
                }
                if let Some(g) = &c.gas {
                    g.visit(f);
                }
                for a in &c.args {
                    a.visit(f);
                }
            }
            ExprKind::Unary { operand, .. } => operand.visit(f),
            ExprKind::Binary { lhs, rhs, .. } => {
                lhs.visit(f);
                rhs.visit(f);
            }
            ExprKind::Assign { target, value, .. } => {
                target.visit(f);
                value.visit(f);
            }
            ExprKind::Ternary { cond, then_e, else_e } => {
                cond.visit(f);
                then_e.visit(f);
                else_e.visit(f);
            }
            ExprKind::Tuple(items) | ExprKind::ArrayLit(items) => {
                for it in items.iter().flatten() {
                    it.visit(f);
                }
            }
            ExprKind::New(inner) => inner.visit(f),
            ExprKind::Ident(_) | ExprKind::Lit(_) | ExprKind::TypeName(_) | ExprKind::Unsupported => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExprKind {
    /// A bare identifier (`x`, `owner`, `balances`).
    Ident(String),
    /// `base.member`
    Member { base: Box<Expr>, member: String },
    /// `base[index]` (index `None` for `base[]` in type positions).
    Index { base: Box<Expr>, index: Option<Box<Expr>> },
    /// A function/method/low-level/cast/builtin call.
    Call(Call),
    /// A literal.
    Lit(Lit),
    /// Unary op.
    Unary { op: UnOp, operand: Box<Expr> },
    /// Binary op.
    Binary { op: BinOp, lhs: Box<Expr>, rhs: Box<Expr> },
    /// Assignment (`=`, `+=`, ...). `target` is an lvalue.
    Assign { op: AssignOp, target: Box<Expr>, value: Box<Expr> },
    /// `cond ? then_e : else_e`
    Ternary { cond: Box<Expr>, then_e: Box<Expr>, else_e: Box<Expr> },
    /// `(a, b, c)` — components may be empty (`(, x)`).
    Tuple(Vec<Option<Expr>>),
    /// A type name in expression position (`address`, `uint256`, `IERC20`).
    TypeName(String),
    /// `new Foo`
    New(Box<Expr>),
    /// `[a, b, c]`
    ArrayLit(Vec<Option<Expr>>),
    /// Anything we chose not to model precisely.
    Unsupported,
}

/// A call site, pre-classified by shape and callee name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    /// The full callee expression (e.g. `token.transfer`).
    pub callee: Box<Expr>,
    /// For member calls `recv.method(...)`, the receiver `recv`.
    pub receiver: Option<Box<Expr>>,
    /// Best-effort resolved method/function name (`transfer`, `call`, `ecrecover`).
    pub func_name: Option<String>,
    /// Positional arguments.
    pub args: Vec<Expr>,
    /// `{value: ...}` on the call, if present (ETH sent).
    pub value: Option<Box<Expr>>,
    /// `{gas: ...}` on the call, if present.
    pub gas: Option<Box<Expr>>,
    /// Classification.
    pub kind: CallKind,
}

/// Classification of a call, determined at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallKind {
    /// `foo(...)` resolved to the same contract / inherited / internal.
    Internal,
    /// `other.foo(...)` to a different contract / interface (a trust frontier).
    External,
    /// `addr.call{...}(...)` — raw low-level call.
    LowLevelCall,
    /// `addr.delegatecall(...)`.
    DelegateCall,
    /// `addr.staticcall(...)`.
    StaticCall,
    /// `addr.send(...)`.
    Send,
    /// `addr.transfer(...)`.
    Transfer,
    /// `new Foo(...)` contract creation.
    New,
    /// A type cast: `address(x)`, `uint256(x)`, `payable(x)`, `IERC20(x)`.
    TypeCast,
    /// A recognized builtin / global function.
    Builtin(Builtin),
    /// Unclassified (could not determine).
    Unknown,
}

impl CallKind {
    /// True for any call that hands control flow to a potentially untrusted
    /// external contract — the surface where reentrancy and trust-frontier bugs
    /// live.
    pub fn is_external_transfer_of_control(self) -> bool {
        matches!(
            self,
            CallKind::External
                | CallKind::LowLevelCall
                | CallKind::DelegateCall
                | CallKind::StaticCall
                | CallKind::Send
                | CallKind::Transfer
        )
    }

    /// True if this call can send native ETH (and thus trigger `receive`/`fallback`).
    pub fn can_send_value(self) -> bool {
        matches!(self, CallKind::LowLevelCall | CallKind::Send | CallKind::Transfer)
    }
}

/// Recognized builtin / global functions relevant to security analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Builtin {
    Require,
    Assert,
    Revert,
    Keccak256,
    Sha256,
    Ripemd160,
    /// `ecrecover(hash, v, r, s)` — signature recovery.
    Ecrecover,
    AbiEncode,
    AbiEncodePacked,
    AbiEncodeWithSelector,
    AbiEncodeWithSignature,
    AbiDecode,
    Selfdestruct,
    Blockhash,
    Gasleft,
    /// `addmod` / `mulmod`.
    ModMath,
    /// `push`/`pop` on a dynamic array (used by DoS / unbounded-growth detectors).
    ArrayPushPop,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Lit {
    Number(String),
    /// Hex number literal (`0x...`).
    HexNumber(String),
    Bool(bool),
    String(String),
    Address(String),
    HexBytes(String),
    /// `block.timestamp` etc. are *not* literals — they are member accesses.
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnOp {
    Not,
    BitNot,
    Negate,
    PreInc,
    PreDec,
    PostInc,
    PostDec,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Shl,
    Shr,
    BitAnd,
    BitOr,
    BitXor,
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl BinOp {
    pub fn is_comparison(self) -> bool {
        matches!(self, BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge)
    }
    pub fn is_arithmetic(self) -> bool {
        matches!(self, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Pow)
    }
    /// A relational ordering comparison (used to recognize bounds checks).
    pub fn is_ordering(self) -> bool {
        matches!(self, BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssignOp {
    Assign,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// Provenance label for a value — the smart-contract analog of `vortex`'s
/// entropy *sources*. A value can carry several at once (tracked as a set in
/// `sluice-dataflow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ValueSource {
    /// Parameters of externally-callable functions, `msg.data`, calldata.
    AttackerInput,
    /// `msg.sender`.
    MsgSender,
    /// `msg.value`.
    MsgValue,
    /// `tx.origin`.
    TxOrigin,
    /// Value returned from an external / low-level / static call.
    ExternalReturn,
    /// A price-like quantity: `balanceOf(pool)`, `getReserves`, `slot0`,
    /// `pricePerShare`, `get_virtual_price`, or `totalSupply` used as a divisor.
    PriceLike,
    /// `block.timestamp`, `block.number`, `block.prevrandao`, `blockhash`, etc.
    BlockEnv,
    /// Read from contract storage (a state variable).
    StorageState,
    /// A compile-time constant.
    Constant,
    /// Unknown / unmodeled.
    Unknown,
}
