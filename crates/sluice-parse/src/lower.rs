//! Lowering from `solang_parser::pt` AST nodes into normalized SCIR
//! ([`sluice_ir`]) expressions and statements, including call classification.

use rustc_hash::FxHashSet;
use sluice_ir::{
    AssignOp, BinOp, Builtin, Call, CallKind, CatchClause, Expr, ExprKind, Lit, Span, Stmt, StmtKind, UnOp,
};
use solang_parser::pt;

/// Lowers AST nodes for a single source file.
pub struct Lowerer<'a> {
    pub file_no: u32,
    /// The file source, used to slice inline-assembly blocks textually.
    pub src: &'a str,
    /// Names of all declared contracts/interfaces (for cast detection).
    pub known_types: &'a FxHashSet<String>,
    /// Names of declared libraries (for namespace-call detection).
    pub known_libraries: &'a FxHashSet<String>,
    /// Function names declared in libraries. A member call `x.fn(...)` whose
    /// method is one of these is a `using`-bound internal library call (e.g.
    /// `digest.recover(sig)`, `token.safeTransfer(...)`), not an external call.
    pub known_lib_funcs: &'a FxHashSet<String>,
}

impl<'a> Lowerer<'a> {
    pub fn span(&self, loc: pt::Loc) -> Span {
        match loc {
            pt::Loc::File(_, s, e) => Span::new(self.file_no, s as u32, e as u32),
            _ => Span::dummy(),
        }
    }

    // ---------------------------------------------------------------- statements

    /// Lower a function body (the top-level `{ ... }`) into a flat statement vec.
    pub fn lower_body(&self, body: &pt::Statement) -> Vec<Stmt> {
        match body {
            pt::Statement::Block { statements, .. } => {
                statements.iter().map(|s| self.lower_stmt(s)).collect()
            }
            other => vec![self.lower_stmt(other)],
        }
    }

    /// Lower a statement that may be a block or a single statement into a vec
    /// (used for `if`/`while`/`for` branch bodies).
    fn lower_branch(&self, s: &pt::Statement) -> Vec<Stmt> {
        match s {
            pt::Statement::Block { statements, .. } => {
                statements.iter().map(|x| self.lower_stmt(x)).collect()
            }
            other => vec![self.lower_stmt(other)],
        }
    }

    pub fn lower_stmt(&self, s: &pt::Statement) -> Stmt {
        let span = self.span(stmt_loc(s));
        let kind = match s {
            pt::Statement::Block { unchecked, statements, .. } => StmtKind::Block {
                unchecked: *unchecked,
                stmts: statements.iter().map(|x| self.lower_stmt(x)).collect(),
            },
            pt::Statement::Assembly { loc, .. } => self.lower_assembly(*loc),
            pt::Statement::Args(..) => StmtKind::Unsupported,
            pt::Statement::If(_, cond, then_s, else_s) => StmtKind::If {
                cond: self.lower_expr(cond),
                then_branch: self.lower_branch(then_s),
                else_branch: else_s.as_ref().map(|e| self.lower_branch(e)).unwrap_or_default(),
            },
            pt::Statement::While(_, cond, body) => StmtKind::While {
                cond: self.lower_expr(cond),
                body: self.lower_branch(body),
            },
            pt::Statement::Expression(_, e) => StmtKind::Expr(self.lower_expr(e)),
            pt::Statement::VariableDefinition(_, decl, init) => StmtKind::VarDecl {
                name: decl.name.as_ref().map(|i| i.name.clone()),
                ty: sol_type_text(&decl.ty),
                init: init.as_ref().map(|e| self.lower_expr(e)),
            },
            pt::Statement::For(_, init, cond, step, body) => StmtKind::For {
                init: init.as_ref().map(|s| Box::new(self.lower_stmt(s))),
                cond: cond.as_ref().map(|e| self.lower_expr(e)),
                step: step.as_ref().map(|e| self.lower_expr(e)),
                body: body.as_ref().map(|b| self.lower_branch(b)).unwrap_or_default(),
            },
            pt::Statement::DoWhile(_, body, cond) => StmtKind::DoWhile {
                body: self.lower_branch(body),
                cond: self.lower_expr(cond),
            },
            pt::Statement::Continue(_) => StmtKind::Continue,
            pt::Statement::Break(_) => StmtKind::Break,
            pt::Statement::Return(_, e) => StmtKind::Return(e.as_ref().map(|e| self.lower_expr(e))),
            pt::Statement::Revert(_, path, args) => StmtKind::Revert {
                error: path.as_ref().map(ident_path_text),
                args: args.iter().map(|a| self.lower_expr(a)).collect(),
            },
            pt::Statement::RevertNamedArgs(_, path, args) => StmtKind::Revert {
                error: path.as_ref().map(ident_path_text),
                args: args.iter().map(|a| self.lower_expr(&a.expr)).collect(),
            },
            pt::Statement::Emit(_, e) => StmtKind::Emit(self.lower_expr(e)),
            pt::Statement::Try(_, expr, returns, catches) => {
                let ret_names = returns
                    .as_ref()
                    .map(|(params, _)| param_names(params))
                    .unwrap_or_default();
                let body = returns
                    .as_ref()
                    .map(|(_, b)| self.lower_branch(b))
                    .unwrap_or_default();
                StmtKind::Try {
                    expr: self.lower_expr(expr),
                    returns: ret_names,
                    body,
                    catches: catches.iter().map(|c| self.lower_catch(c)).collect(),
                }
            }
            pt::Statement::Error(_) => StmtKind::Unsupported,
        };
        // Recognize the modifier placeholder `_;` (parsed as an expression stmt
        // whose expression is the variable `_`).
        if let StmtKind::Expr(e) = &kind {
            if matches!(&e.kind, ExprKind::Ident(n) if n == "_") {
                return Stmt::new(span, StmtKind::Placeholder);
            }
        }
        Stmt::new(span, kind)
    }

    fn lower_catch(&self, c: &pt::CatchClause) -> CatchClause {
        match c {
            pt::CatchClause::Simple(_, param, body) => CatchClause {
                selector: None,
                param: param.as_ref().and_then(|p| p.name.as_ref().map(|i| i.name.clone())),
                body: self.lower_branch(body),
            },
            pt::CatchClause::Named(_, id, param, body) => CatchClause {
                selector: Some(id.name.clone()),
                param: param.name.as_ref().map(|i| i.name.clone()),
                body: self.lower_branch(body),
            },
        }
    }

    /// Summarize an inline-assembly block by textually scanning its source.
    fn lower_assembly(&self, loc: pt::Loc) -> StmtKind {
        let text = match loc {
            pt::Loc::File(_, s, e) => self.src.get(s..e).unwrap_or(""),
            _ => "",
        };
        let count = |needle: &str| text.matches(needle).count();
        let n_sstore = count("sstore(");
        StmtKind::Assembly {
            sstore_slots: std::iter::repeat_n(String::from("sstore"), n_sstore).collect(),
            has_call: text.contains("call(")
                || text.contains("delegatecall(")
                || text.contains("staticcall(")
                || text.contains("callcode("),
            has_terminator: text.contains("return(")
                || text.contains("revert(")
                || text.contains("selfdestruct(")
                || text.contains("stop("),
        }
    }

    // ---------------------------------------------------------------- expressions

    pub fn lower_expr(&self, e: &pt::Expression) -> Expr {
        use pt::Expression as E;
        let span = self.span(expr_loc(e));
        let kind = match e {
            E::PostIncrement(_, x) => un(UnOp::PostInc, self.lower_expr(x)),
            E::PostDecrement(_, x) => un(UnOp::PostDec, self.lower_expr(x)),
            E::PreIncrement(_, x) => un(UnOp::PreInc, self.lower_expr(x)),
            E::PreDecrement(_, x) => un(UnOp::PreDec, self.lower_expr(x)),
            E::Not(_, x) => un(UnOp::Not, self.lower_expr(x)),
            E::BitwiseNot(_, x) => un(UnOp::BitNot, self.lower_expr(x)),
            E::Negate(_, x) => un(UnOp::Negate, self.lower_expr(x)),
            E::Delete(_, x) => un(UnOp::Delete, self.lower_expr(x)),
            E::UnaryPlus(_, x) => return self.lower_expr(x), // no-op
            E::Parenthesis(_, x) => return self.lower_expr(x),

            E::New(_, ty) => ExprKind::New(Box::new(self.lower_expr(ty))),
            E::ArraySubscript(_, base, idx) => ExprKind::Index {
                base: Box::new(self.lower_expr(base)),
                index: idx.as_ref().map(|i| Box::new(self.lower_expr(i))),
            },
            E::ArraySlice(_, base, _, _) => ExprKind::Index {
                base: Box::new(self.lower_expr(base)),
                index: None,
            },
            E::MemberAccess(_, base, member) => ExprKind::Member {
                base: Box::new(self.lower_expr(base)),
                member: member.name.clone(),
            },

            E::FunctionCall(_, callee, args) => self.lower_call(callee, args, &[]),
            E::FunctionCallBlock(_, callee, block) => {
                // A call with options but (syntactically) no positional args here.
                let named = args_block_named(block);
                self.lower_call_parts(callee, &[], named)
            }
            E::NamedFunctionCall(_, callee, named) => {
                let args: Vec<&pt::Expression> = named.iter().map(|n| &n.expr).collect();
                self.lower_call(callee, &collect_refs(&args), &[])
            }

            E::Power(_, a, b) => self.bin(BinOp::Pow, a, b),
            E::Multiply(_, a, b) => self.bin(BinOp::Mul, a, b),
            E::Divide(_, a, b) => self.bin(BinOp::Div, a, b),
            E::Modulo(_, a, b) => self.bin(BinOp::Mod, a, b),
            E::Add(_, a, b) => self.bin(BinOp::Add, a, b),
            E::Subtract(_, a, b) => self.bin(BinOp::Sub, a, b),
            E::ShiftLeft(_, a, b) => self.bin(BinOp::Shl, a, b),
            E::ShiftRight(_, a, b) => self.bin(BinOp::Shr, a, b),
            E::BitwiseAnd(_, a, b) => self.bin(BinOp::BitAnd, a, b),
            E::BitwiseXor(_, a, b) => self.bin(BinOp::BitXor, a, b),
            E::BitwiseOr(_, a, b) => self.bin(BinOp::BitOr, a, b),
            E::Less(_, a, b) => self.bin(BinOp::Lt, a, b),
            E::More(_, a, b) => self.bin(BinOp::Gt, a, b),
            E::LessEqual(_, a, b) => self.bin(BinOp::Le, a, b),
            E::MoreEqual(_, a, b) => self.bin(BinOp::Ge, a, b),
            E::Equal(_, a, b) => self.bin(BinOp::Eq, a, b),
            E::NotEqual(_, a, b) => self.bin(BinOp::Ne, a, b),
            E::And(_, a, b) => self.bin(BinOp::And, a, b),
            E::Or(_, a, b) => self.bin(BinOp::Or, a, b),

            E::ConditionalOperator(_, c, t, f) => ExprKind::Ternary {
                cond: Box::new(self.lower_expr(c)),
                then_e: Box::new(self.lower_expr(t)),
                else_e: Box::new(self.lower_expr(f)),
            },

            E::Assign(_, t, v) => self.assign(AssignOp::Assign, t, v),
            E::AssignOr(_, t, v) => self.assign(AssignOp::BitOr, t, v),
            E::AssignAnd(_, t, v) => self.assign(AssignOp::BitAnd, t, v),
            E::AssignXor(_, t, v) => self.assign(AssignOp::BitXor, t, v),
            E::AssignShiftLeft(_, t, v) => self.assign(AssignOp::Shl, t, v),
            E::AssignShiftRight(_, t, v) => self.assign(AssignOp::Shr, t, v),
            E::AssignAdd(_, t, v) => self.assign(AssignOp::Add, t, v),
            E::AssignSubtract(_, t, v) => self.assign(AssignOp::Sub, t, v),
            E::AssignMultiply(_, t, v) => self.assign(AssignOp::Mul, t, v),
            E::AssignDivide(_, t, v) => self.assign(AssignOp::Div, t, v),
            E::AssignModulo(_, t, v) => self.assign(AssignOp::Mod, t, v),

            E::BoolLiteral(_, b) => ExprKind::Lit(Lit::Bool(*b)),
            E::NumberLiteral(_, v, _, _) => ExprKind::Lit(Lit::Number(v.clone())),
            E::RationalNumberLiteral(_, m, f, _, _) => {
                ExprKind::Lit(Lit::Number(format!("{m}.{f}")))
            }
            E::HexNumberLiteral(_, v, _) => ExprKind::Lit(Lit::HexNumber(v.clone())),
            E::StringLiteral(parts) => {
                ExprKind::Lit(Lit::String(parts.iter().map(|p| p.string.clone()).collect()))
            }
            E::HexLiteral(parts) => {
                ExprKind::Lit(Lit::HexBytes(parts.iter().map(|p| p.hex.clone()).collect()))
            }
            E::AddressLiteral(_, a) => ExprKind::Lit(Lit::Address(a.clone())),
            E::Type(_, ty) => ExprKind::TypeName(type_text(ty)),
            E::Variable(id) => ExprKind::Ident(id.name.clone()),
            E::List(_, params) => ExprKind::Tuple(
                params
                    .iter()
                    .map(|(_, p)| p.as_ref().map(|p| self.lower_expr(&p.ty)))
                    .collect(),
            ),
            E::ArrayLiteral(_, items) => {
                ExprKind::ArrayLit(items.iter().map(|i| Some(self.lower_expr(i))).collect())
            }
        };
        Expr::new(span, kind)
    }

    fn bin(&self, op: BinOp, a: &pt::Expression, b: &pt::Expression) -> ExprKind {
        ExprKind::Binary {
            op,
            lhs: Box::new(self.lower_expr(a)),
            rhs: Box::new(self.lower_expr(b)),
        }
    }

    fn assign(&self, op: AssignOp, t: &pt::Expression, v: &pt::Expression) -> ExprKind {
        ExprKind::Assign {
            op,
            target: Box::new(self.lower_expr(t)),
            value: Box::new(self.lower_expr(v)),
        }
    }

    // ---------------------------------------------------------------- calls

    fn lower_call(
        &self,
        callee: &pt::Expression,
        args: &[pt::Expression],
        extra_named: &[pt::NamedArgument],
    ) -> ExprKind {
        let arg_refs: Vec<&pt::Expression> = args.iter().collect();
        self.lower_call_parts(callee, &arg_refs, extra_named.to_vec())
    }

    fn lower_call_parts(
        &self,
        callee: &pt::Expression,
        args: &[&pt::Expression],
        named_opts: Vec<pt::NamedArgument>,
    ) -> ExprKind {
        // Peel a `{value:..,gas:..}` options block off the callee.
        let mut value = None;
        let mut gas = None;
        let real_callee = match callee {
            pt::Expression::FunctionCallBlock(_, inner, block) => {
                for na in args_block_named(block) {
                    match na.name.name.as_str() {
                        "value" => value = Some(Box::new(self.lower_expr(&na.expr))),
                        "gas" => gas = Some(Box::new(self.lower_expr(&na.expr))),
                        _ => {}
                    }
                }
                inner.as_ref()
            }
            other => other,
        };
        for na in &named_opts {
            match na.name.name.as_str() {
                "value" => value = Some(Box::new(self.lower_expr(&na.expr))),
                "gas" => gas = Some(Box::new(self.lower_expr(&na.expr))),
                _ => {}
            }
        }

        let lowered_args: Vec<Expr> = args.iter().map(|a| self.lower_expr(a)).collect();
        let n_args = lowered_args.len();

        let (kind, receiver, func_name) = self.classify(real_callee, n_args, value.is_some());

        ExprKind::Call(Call {
            callee: Box::new(self.lower_expr(real_callee)),
            receiver,
            func_name,
            args: lowered_args,
            value,
            gas,
            kind,
        })
    }

    /// Classify a callee expression into a [`CallKind`], plus the receiver
    /// (for member calls) and resolved method name.
    fn classify(
        &self,
        callee: &pt::Expression,
        n_args: usize,
        has_value: bool,
    ) -> (CallKind, Option<Box<Expr>>, Option<String>) {
        use pt::Expression as E;
        match callee {
            // `new Foo(...)`
            E::New(..) => (CallKind::New, None, None),
            // `address(x)`, `uint256(x)`, `payable(x)`
            E::Type(..) => (CallKind::TypeCast, None, None),
            // bare function name
            E::Variable(id) => {
                let name = id.name.as_str();
                if let Some(b) = builtin_for(name) {
                    (CallKind::Builtin(b), None, Some(name.to_string()))
                } else if self.known_types.contains(name) {
                    // `IERC20(addr)` / `MyContract(addr)` — a cast.
                    (CallKind::TypeCast, None, Some(name.to_string()))
                } else {
                    (CallKind::Internal, None, Some(name.to_string()))
                }
            }
            // `recv.method`
            E::MemberAccess(_, base, member) => {
                let m = member.name.as_str();
                let recv = self.lower_expr(base);
                let recv_root = root_ident(&recv).unwrap_or("").to_string();
                let kind = match m {
                    "call" => CallKind::LowLevelCall,
                    "delegatecall" => CallKind::DelegateCall,
                    "staticcall" | "callcode" => CallKind::StaticCall,
                    "send" => CallKind::Send,
                    // `addr.transfer(amt)` is ETH; `token.transfer(to,amt)` is ERC20.
                    "transfer" if n_args <= 1 && !is_token_like(&recv_root) => CallKind::Transfer,
                    "transfer" | "transferFrom" => CallKind::External,
                    _ => {
                        if recv_root == "abi" {
                            CallKind::Builtin(abi_builtin(m))
                        } else if recv_root == "super" {
                            CallKind::Internal
                        } else if (m == "push" || m == "pop") && self.known_types.is_empty() {
                            CallKind::Builtin(Builtin::ArrayPushPop)
                        } else if m == "push" || m == "pop" {
                            CallKind::Builtin(Builtin::ArrayPushPop)
                        } else if self.known_libraries.contains(&recv_root) {
                            // `Math.max(...)`, `SafeMath.add(...)` — internal lib call.
                            CallKind::Internal
                        } else if self.known_lib_funcs.contains(m) {
                            // `using L for T` bound call: `digest.recover(sig)`,
                            // `token.safeTransfer(...)` — internal, reverts on failure.
                            CallKind::Internal
                        } else {
                            CallKind::External
                        }
                    }
                };
                // ETH-sending member calls imply value movement even without {value:}.
                let _ = has_value;
                (kind, Some(Box::new(recv)), Some(m.to_string()))
            }
            E::FunctionCall(..) | E::FunctionCallBlock(..) | E::NamedFunctionCall(..) => {
                // e.g. `factory.create()(...)` — treat the outer as external.
                (CallKind::External, None, None)
            }
            _ => (CallKind::Unknown, None, None),
        }
    }
}

// -------------------------------------------------------------------- helpers

fn un(op: UnOp, operand: Expr) -> ExprKind {
    ExprKind::Unary { op, operand: Box::new(operand) }
}

/// Root identifier name of an lvalue/expression chain (`balances[x].y` -> `balances`).
pub fn root_ident(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        ExprKind::Member { base, .. } => root_ident(base),
        ExprKind::Index { base, .. } => root_ident(base),
        _ => None,
    }
}

/// Heuristic: does this receiver name look like an ERC20 token handle (so a
/// `.transfer(to, amt)` is a token transfer rather than ETH)?
fn is_token_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("token") || n.contains("erc20") || n.contains("asset") || n.contains("coin")
        || n == "want" || n == "underlying" || n == "weth" || n == "usdc" || n == "dai"
}

fn builtin_for(name: &str) -> Option<Builtin> {
    Some(match name {
        "require" => Builtin::Require,
        "assert" => Builtin::Assert,
        "revert" => Builtin::Revert,
        "keccak256" | "sha3" => Builtin::Keccak256,
        "sha256" => Builtin::Sha256,
        "ripemd160" => Builtin::Ripemd160,
        "ecrecover" => Builtin::Ecrecover,
        "selfdestruct" | "suicide" => Builtin::Selfdestruct,
        "blockhash" => Builtin::Blockhash,
        "gasleft" => Builtin::Gasleft,
        "addmod" | "mulmod" => Builtin::ModMath,
        _ => return None,
    })
}

fn abi_builtin(member: &str) -> Builtin {
    match member {
        "encode" => Builtin::AbiEncode,
        "encodePacked" => Builtin::AbiEncodePacked,
        "encodeWithSelector" => Builtin::AbiEncodeWithSelector,
        "encodeWithSignature" | "encodeCall" => Builtin::AbiEncodeWithSignature,
        "decode" => Builtin::AbiDecode,
        _ => Builtin::Other,
    }
}

fn args_block_named(block: &pt::Statement) -> Vec<pt::NamedArgument> {
    match block {
        pt::Statement::Args(_, named) => named.clone(),
        _ => Vec::new(),
    }
}

fn collect_refs<'b>(v: &[&'b pt::Expression]) -> Vec<pt::Expression> {
    v.iter().map(|e| (*e).clone()).collect()
}

pub fn ident_path_text(p: &pt::IdentifierPath) -> String {
    p.identifiers.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(".")
}

pub fn param_names(params: &pt::ParameterList) -> Vec<String> {
    params
        .iter()
        .filter_map(|(_, p)| p.as_ref().and_then(|p| p.name.as_ref().map(|i| i.name.clone())))
        .collect()
}

/// Render a `solang` type expression to a compact textual type.
pub fn sol_type_text(e: &pt::Expression) -> String {
    use pt::Expression as E;
    match e {
        E::Type(_, ty) => type_text(ty),
        E::Variable(id) => id.name.clone(),
        E::MemberAccess(_, base, m) => format!("{}.{}", sol_type_text(base), m.name),
        E::ArraySubscript(_, base, Some(n)) => format!("{}[{}]", sol_type_text(base), sol_type_text(n)),
        E::ArraySubscript(_, base, None) => format!("{}[]", sol_type_text(base)),
        E::Parenthesis(_, inner) => sol_type_text(inner),
        E::NumberLiteral(_, v, _, _) => v.clone(),
        E::FunctionCall(_, c, _) => sol_type_text(c),
        _ => "<type>".to_string(),
    }
}

fn type_text(ty: &pt::Type) -> String {
    use pt::Type as T;
    match ty {
        T::Address => "address".into(),
        T::AddressPayable => "address payable".into(),
        T::Payable => "payable".into(),
        T::Bool => "bool".into(),
        T::String => "string".into(),
        T::Int(n) => format!("int{n}"),
        T::Uint(n) => format!("uint{n}"),
        T::Bytes(n) => format!("bytes{n}"),
        T::Rational => "fixed".into(),
        T::DynamicBytes => "bytes".into(),
        T::Mapping { key, value, .. } => {
            format!("mapping({} => {})", sol_type_text(key), sol_type_text(value))
        }
        T::Function { .. } => "function".into(),
    }
}

fn expr_loc(e: &pt::Expression) -> pt::Loc {
    use pt::CodeLocation;
    e.loc()
}

fn stmt_loc(s: &pt::Statement) -> pt::Loc {
    use pt::CodeLocation;
    s.loc()
}
