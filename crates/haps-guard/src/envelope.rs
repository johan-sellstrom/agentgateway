//! RP-CORE-08: envelope constraints.
//!
//! HAPS lets an AI-INTENT carry `constraints.envelope`, bounds within which the executed action
//! may vary without a new approval, but leaves the meaning of each envelope member to the
//! intent's profile, and v0.4 defines no profile that gives any member a meaning. So the guard
//! defines its own small vocabulary, configured per tool: each envelope member the guard can
//! enforce is named in the tool's rules, with the kind of check and the argument it governs.
//! A member with no rule cannot be enforced, and the call is refused; the guard never ignores a
//! constraint it does not understand.
//!
//! Two kinds:
//!
//! - `decimalRange` — `{currency?, min?, max?}`, the bounds decimal strings. The governed
//!   argument is either a decimal string or `{currency, value}`. Monetary amounts are strings in
//!   HAPS, so the comparison is decimal, never floating point.
//! - `allowList` — an array. The governed argument matches an object entry when it holds every
//!   member of the entry with an equal value, and any other entry when it equals it.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use haps_canon::Value as Canon;

/// One configured envelope rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeRule {
	pub kind: RuleKind,
	/// The argument the rule governs.
	pub path: Pointer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
	DecimalRange,
	AllowList,
}

/// A JSON Pointer (RFC 6901) into the call's arguments. Object members only: tool arguments
/// are an object, and no rule needs to reach into an array.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pointer(Vec<Vec<u8>>);

impl Pointer {
	pub fn parse(s: &str) -> Result<Self, String> {
		let rest = s
			.strip_prefix('/')
			.ok_or_else(|| format!("{s:?} is not a JSON Pointer: it must start with '/'"))?;
		let mut segments = Vec::new();
		for raw in rest.split('/') {
			if raw.is_empty() {
				return Err(format!("{s:?} has an empty segment"));
			}
			// RFC 6901: ~1 is '/', ~0 is '~', and no other escape exists.
			let mut seg = String::new();
			let mut chars = raw.chars();
			while let Some(c) = chars.next() {
				match c {
					'~' => match chars.next() {
						Some('0') => seg.push('~'),
						Some('1') => seg.push('/'),
						_ => return Err(format!("{s:?} has an invalid '~' escape")),
					},
					c => seg.push(c),
				}
			}
			segments.push(seg.into_bytes());
		}
		Ok(Self(segments))
	}

	fn get<'a>(&self, mut v: &'a Canon) -> Option<&'a Canon> {
		for seg in &self.0 {
			v = member_bytes(v, seg)?;
		}
		Some(v)
	}

	/// `v` with the member this pointer names removed, if it exists.
	fn remove(&self, v: &Canon) -> Canon {
		fn go(v: &Canon, segs: &[Vec<u8>]) -> Canon {
			let (Some(first), Canon::Object(members)) = (segs.first(), v) else {
				return v.clone();
			};
			let rest = &segs[1..];
			Canon::Object(
				members
					.iter()
					.filter(|(k, _)| !(rest.is_empty() && k == first))
					.map(|(k, child)| {
						if k == first {
							(k.clone(), go(child, rest))
						} else {
							(k.clone(), child.clone())
						}
					})
					.collect(),
			)
		}
		go(v, &self.0)
	}
}

impl fmt::Display for Pointer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for seg in &self.0 {
			let s = String::from_utf8_lossy(seg)
				.replace('~', "~0")
				.replace('/', "~1");
			write!(f, "/{s}")?;
		}
		Ok(())
	}
}

/// Why an envelope refused a call.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
	/// The envelope holds a member this tool has no rule for.
	Unenforceable(String),
	/// The envelope or its rule is malformed, so it cannot be evaluated.
	Malformed { member: String, why: String },
	/// The call's arguments fall outside the envelope.
	Outside { member: String, why: String },
}

impl fmt::Display for EnvelopeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			EnvelopeError::Unenforceable(m) => write!(
				f,
				"the approval's envelope constraint {m:?} cannot be enforced here, so the approval cannot be honoured"
			),
			EnvelopeError::Malformed { member, why } => {
				write!(f, "envelope constraint {member:?} is malformed: {why}")
			},
			EnvelopeError::Outside { member, why } => write!(
				f,
				"tool arguments fall outside the approved envelope ({member}: {why}); request a new approval"
			),
		}
	}
}

/// Enforce every member of `envelope` against `arguments`, returning the paths the envelope
/// governs. `envelope` is the intent's `constraints.envelope`, already strictly parsed.
pub fn enforce(
	envelope: &Canon,
	arguments: &Canon,
	rules: &HashMap<String, EnvelopeRule>,
) -> Result<Vec<Pointer>, EnvelopeError> {
	let Canon::Object(members) = envelope else {
		return Err(EnvelopeError::Malformed {
			member: "envelope".into(),
			why: "not an object".into(),
		});
	};
	let mut governed = Vec::new();
	for (key, bound) in members {
		let name = String::from_utf8_lossy(key).into_owned();
		let rule = rules
			.get(&name)
			.ok_or_else(|| EnvelopeError::Unenforceable(name.clone()))?;
		let target = rule
			.path
			.get(arguments)
			.ok_or_else(|| EnvelopeError::Outside {
				member: name.clone(),
				why: format!("argument {} is missing", rule.path),
			})?;
		match rule.kind {
			RuleKind::DecimalRange => decimal_range(&name, bound, target)?,
			RuleKind::AllowList => allow_list(&name, bound, target)?,
		}
		governed.push(rule.path.clone());
	}
	Ok(governed)
}

/// `v` with every governed path removed: what must still match the approval exactly when the
/// envelope permits the governed values to vary.
pub fn without(v: &Canon, governed: &[Pointer]) -> Canon {
	governed.iter().fold(v.clone(), |acc, p| p.remove(&acc))
}

fn decimal_range(name: &str, bound: &Canon, target: &Canon) -> Result<(), EnvelopeError> {
	let malformed = |why: &str| EnvelopeError::Malformed {
		member: name.into(),
		why: why.into(),
	};
	let outside = |why: String| EnvelopeError::Outside {
		member: name.into(),
		why,
	};
	if !matches!(bound, Canon::Object(_)) {
		return Err(malformed("a decimal range must be an object"));
	}
	let bound_str = |k: &str| -> Result<Option<&str>, EnvelopeError> {
		match member(bound, k) {
			None => Ok(None),
			Some(Canon::Str(s)) => std::str::from_utf8(s)
				.map(Some)
				.map_err(|_| malformed("not UTF-8")),
			Some(_) => Err(malformed(&format!("{k} must be a string"))),
		}
	};
	let currency = bound_str("currency")?;
	let min = bound_str("min")?.map(Decimal::parse).transpose();
	let max = bound_str("max")?.map(Decimal::parse).transpose();
	let (min, max) = (
		min.map_err(|e| malformed(&format!("min: {e}")))?,
		max.map_err(|e| malformed(&format!("max: {e}")))?,
	);
	if min.is_none() && max.is_none() {
		return Err(malformed("a decimal range needs min, max or both"));
	}

	let (value, target_currency) = match target {
		Canon::Str(s) => (s.as_slice(), None),
		Canon::Object(_) => match (member(target, "value"), member(target, "currency")) {
			(Some(Canon::Str(v)), Some(Canon::Str(c))) => (v.as_slice(), Some(c.as_slice())),
			(Some(Canon::Str(v)), None) => (v.as_slice(), None),
			_ => return Err(outside("the argument has no decimal string value".into())),
		},
		_ => return Err(outside("the argument is not a decimal string".into())),
	};
	if let Some(c) = currency
		&& target_currency != Some(c.as_bytes())
	{
		return Err(outside(format!("currency must be {c}")));
	}
	let value = std::str::from_utf8(value)
		.ok()
		.and_then(|v| Decimal::parse(v).ok())
		.ok_or_else(|| outside("the argument is not a decimal string".into()))?;
	if let Some(min) = &min
		&& value.cmp(min) == Ordering::Less
	{
		return Err(outside(format!("{value} is below {min}")));
	}
	if let Some(max) = &max
		&& value.cmp(max) == Ordering::Greater
	{
		return Err(outside(format!("{value} is above {max}")));
	}
	Ok(())
}

fn allow_list(name: &str, bound: &Canon, target: &Canon) -> Result<(), EnvelopeError> {
	let Canon::Array(entries) = bound else {
		return Err(EnvelopeError::Malformed {
			member: name.into(),
			why: "an allow-list must be an array".into(),
		});
	};
	let matches = |entry: &Canon| match entry {
		Canon::Object(required) => required
			.iter()
			.all(|(k, v)| member_bytes(target, k) == Some(v)),
		other => other == target,
	};
	if entries.iter().any(matches) {
		Ok(())
	} else {
		Err(EnvelopeError::Outside {
			member: name.into(),
			why: "the argument matches no allowed entry".into(),
		})
	}
}

fn member<'a>(v: &'a Canon, key: &str) -> Option<&'a Canon> {
	member_bytes(v, key.as_bytes())
}

fn member_bytes<'a>(v: &'a Canon, key: &[u8]) -> Option<&'a Canon> {
	match v {
		Canon::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
		_ => None,
	}
}

/// A decimal string, `-?digits(.digits)?`, compared exactly. No exponent, no leading '+', no
/// bare '.', and at most 64 digits: an amount is a short string, and anything else is refused
/// rather than interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decimal {
	negative: bool,
	/// Integer digits without leading zeros; empty for zero.
	int: Vec<u8>,
	/// Fraction digits without trailing zeros.
	frac: Vec<u8>,
	text: String,
}

impl Decimal {
	pub fn parse(s: &str) -> Result<Self, String> {
		let bad = || format!("{s:?} is not a decimal string");
		let (negative, body) = match s.strip_prefix('-') {
			Some(b) => (true, b),
			None => (false, s),
		};
		let (int, frac) = match body.split_once('.') {
			Some((i, f)) => (i, Some(f)),
			None => (body, None),
		};
		let all_digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
		if !all_digits(int) || frac.is_some_and(|f| !all_digits(f)) {
			return Err(bad());
		}
		if int.len() + frac.map_or(0, str::len) > 64 {
			return Err(format!("{s:?} has more than 64 digits"));
		}
		let int = int.trim_start_matches('0').as_bytes().to_vec();
		let frac = frac.unwrap_or("").trim_end_matches('0').as_bytes().to_vec();
		// Negative zero is zero.
		let negative = negative && !(int.is_empty() && frac.is_empty());
		Ok(Self {
			negative,
			int,
			frac,
			text: s.to_owned(),
		})
	}

	fn cmp_magnitude(&self, other: &Self) -> Ordering {
		self
			.int
			.len()
			.cmp(&other.int.len())
			.then_with(|| self.int.cmp(&other.int))
			// Trailing zeros are trimmed, so lexicographic order on the fraction digits is
			// numeric order.
			.then_with(|| self.frac.cmp(&other.frac))
	}
}

impl Ord for Decimal {
	fn cmp(&self, other: &Self) -> Ordering {
		match (self.negative, other.negative) {
			(false, true) => Ordering::Greater,
			(true, false) => Ordering::Less,
			(false, false) => self.cmp_magnitude(other),
			(true, true) => other.cmp_magnitude(self),
		}
	}
}

impl PartialOrd for Decimal {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl fmt::Display for Decimal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.text)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn canon(s: &str) -> Canon {
		haps_canon::parse(s).unwrap()
	}

	fn d(s: &str) -> Decimal {
		Decimal::parse(s).unwrap()
	}

	#[test]
	fn decimals_compare_exactly() {
		assert_eq!(d("250.00"), d("250.00"));
		assert_eq!(d("250.00").cmp(&d("250")), Ordering::Equal);
		assert_eq!(d("0250.5").cmp(&d("250.50")), Ordering::Equal);
		assert!(d("250.01") > d("250.00"));
		assert!(d("99.99") < d("100"));
		assert!(d("1000") > d("999.999"));
		assert!(d("-1") < d("0"));
		assert!(d("-2") < d("-1.5"));
		assert_eq!(d("-0.00").cmp(&d("0")), Ordering::Equal);
		// Larger than any float can hold exactly.
		assert!(d("90071992547409930.01") > d("90071992547409930.00"));
	}

	#[test]
	fn non_decimal_strings_are_refused() {
		for s in [
			"", "-", ".5", "5.", "1e3", "+1", "1,000", "0x10", " 1", "1.2.3", "NaN",
		] {
			assert!(Decimal::parse(s).is_err(), "{s:?} must be refused");
		}
		assert!(Decimal::parse(&"9".repeat(65)).is_err());
	}

	#[test]
	fn pointers_follow_rfc_6901() {
		let p = Pointer::parse("/a~1b/c~0d").unwrap();
		assert_eq!(p.0, vec![b"a/b".to_vec(), b"c~d".to_vec()]);
		assert_eq!(p.to_string(), "/a~1b/c~0d");
		for bad in ["", "a", "/", "/a//b", "/a~2"] {
			assert!(Pointer::parse(bad).is_err(), "{bad:?} must be refused");
		}
	}

	fn payment_rules() -> HashMap<String, EnvelopeRule> {
		HashMap::from([
			(
				"amountRange".to_owned(),
				EnvelopeRule {
					kind: RuleKind::DecimalRange,
					path: Pointer::parse("/amount").unwrap(),
				},
			),
			(
				"allowedPayees".to_owned(),
				EnvelopeRule {
					kind: RuleKind::AllowList,
					path: Pointer::parse("/to").unwrap(),
				},
			),
		])
	}

	const ENVELOPE: &str = r#"{"amountRange":{"currency":"GBP","min":"200.00","max":"300.00"},"allowedPayees":[{"iban":"GB00EXAMP1E00000000000000"}]}"#;

	fn args(amount: &str, currency: &str, iban: &str) -> Canon {
		canon(&format!(
			r#"{{"amount":{{"currency":"{currency}","value":"{amount}"}},"to":{{"iban":"{iban}","name":"Example Supplier Ltd"}},"reference":"Invoice 18372"}}"#
		))
	}

	#[test]
	fn arguments_inside_the_envelope_pass_and_report_what_is_governed() {
		let governed = enforce(
			&canon(ENVELOPE),
			&args("250.00", "GBP", "GB00EXAMP1E00000000000000"),
			&payment_rules(),
		)
		.unwrap();
		let mut paths: Vec<String> = governed.iter().map(ToString::to_string).collect();
		paths.sort();
		assert_eq!(paths, ["/amount", "/to"]);
	}

	#[test]
	fn the_bounds_are_inclusive() {
		for amount in ["200.00", "300", "300.000"] {
			assert!(
				enforce(
					&canon(ENVELOPE),
					&args(amount, "GBP", "GB00EXAMP1E00000000000000"),
					&payment_rules()
				)
				.is_ok(),
				"{amount}"
			);
		}
	}

	#[test]
	fn arguments_outside_the_envelope_are_refused() {
		let iban = "GB00EXAMP1E00000000000000";
		for (a, c, i) in [
			("300.01", "GBP", iban),
			("199.99", "GBP", iban),
			("250.00", "EUR", iban),
			("250.00", "GBP", "GB00ATTACKER000000000000000"),
			("2.5e2", "GBP", iban),
		] {
			assert!(
				matches!(
					enforce(&canon(ENVELOPE), &args(a, c, i), &payment_rules()),
					Err(EnvelopeError::Outside { .. })
				),
				"{a} {c} {i}"
			);
		}
	}

	#[test]
	fn a_missing_governed_argument_is_refused() {
		let no_amount = canon(r#"{"to":{"iban":"GB00EXAMP1E00000000000000"}}"#);
		assert!(matches!(
			enforce(&canon(ENVELOPE), &no_amount, &payment_rules()),
			Err(EnvelopeError::Outside { .. })
		));
	}

	#[test]
	fn an_envelope_member_without_a_rule_cannot_be_enforced() {
		let envelope = canon(r#"{"maxDailyTotal":"1000.00"}"#);
		assert_eq!(
			enforce(&envelope, &args("250.00", "GBP", "x"), &payment_rules()),
			Err(EnvelopeError::Unenforceable("maxDailyTotal".into()))
		);
	}

	#[test]
	fn malformed_bounds_are_refused_not_ignored() {
		for envelope in [
			r#"{"amountRange":{"currency":"GBP"}}"#,
			r#"{"amountRange":{"min":200}}"#,
			r#"{"amountRange":{"min":"two hundred"}}"#,
			r#"{"amountRange":"200-300"}"#,
			r#"{"allowedPayees":{"iban":"x"}}"#,
		] {
			assert!(
				matches!(
					enforce(
						&canon(envelope),
						&args("250.00", "GBP", "x"),
						&payment_rules()
					),
					Err(EnvelopeError::Malformed { .. })
				),
				"{envelope}"
			);
		}
	}

	#[test]
	fn without_removes_only_the_governed_members() {
		let a = args("250.00", "GBP", "GB00EXAMP1E00000000000000");
		let stripped = without(
			&a,
			&[
				Pointer::parse("/amount").unwrap(),
				Pointer::parse("/to/name").unwrap(),
			],
		);
		assert_eq!(
			haps_canon::canonicalize(&stripped),
			br#"{"reference":"Invoice 18372","to":{"iban":"GB00EXAMP1E00000000000000"}}"#
		);
	}
}
