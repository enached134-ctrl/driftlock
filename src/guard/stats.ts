/**
 * Exact binomial confidence intervals.
 *
 * A guardrail whose entire pitch is that it publishes its own error rate cannot
 * report "0% false positives" from twelve samples as though it meant zero. Twelve
 * clean samples are consistent with a true rate of 26%. Every rate this tool prints
 * carries the interval that the sample size actually supports.
 *
 * Clopper-Pearson rather than Wilson or normal approximation: it is exact, it is
 * conservative, and it does not degenerate at 0/n and n/n - which are precisely the
 * cases a security benchmark reports most often. No dependencies; the regularized
 * incomplete beta is implemented here because pulling in a stats package for one
 * function is not worth the supply-chain surface on a security tool.
 */

export interface Interval {
  point: number;
  lower: number;
  upper: number;
  /** Successes and trials the interval was computed from. */
  k: number;
  n: number;
}

/** Lanczos approximation; accurate to ~15 significant figures for x > 0. */
function logGamma(x: number): number {
  const g = [
    676.5203681218851, -1259.1392167224028, 771.32342877765313,
    -176.61502916214059, 12.507343278686905, -0.13857109526572012,
    9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (x < 0.5) {
    // Reflection formula keeps the series in its accurate range.
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  }
  const z = x - 1;
  let a = 0.99999999999980993;
  const t = z + 7.5;
  for (let i = 0; i < g.length; i++) a += g[i]! / (z + i + 1);
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(a);
}

/**
 * Regularized incomplete beta I_x(a, b), via the Lentz continued fraction.
 * This is the binomial CDF in disguise: P(X <= k) = I_{1-p}(n-k, k+1).
 */
export function incompleteBeta(x: number, a: number, b: number): number {
  if (x <= 0) return 0;
  if (x >= 1) return 1;

  // The fraction converges quickly only on one side of the symmetry point.
  if (x > (a + 1) / (a + b + 2)) return 1 - incompleteBeta(1 - x, b, a);

  const front =
    Math.exp(logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log(1 - x)) / a;

  const TINY = 1e-30;
  let f = 1;
  let c = 1;
  let d = 0;

  for (let i = 0; i <= 300; i++) {
    const m = Math.floor(i / 2);
    let numerator: number;
    if (i === 0) numerator = 1;
    else if (i % 2 === 0) numerator = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m));
    else numerator = -((a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1));

    d = 1 + numerator * d;
    if (Math.abs(d) < TINY) d = TINY;
    d = 1 / d;

    c = 1 + numerator / c;
    if (Math.abs(c) < TINY) c = TINY;

    const delta = c * d;
    f *= delta;

    if (Math.abs(1 - delta) < 1e-14) return front * (f - 1);
  }
  // Non-convergence would silently corrupt a published number; refuse instead.
  throw new Error(`incompleteBeta did not converge for x=${x} a=${a} b=${b}`);
}

/** Inverse of the beta CDF by bisection. Monotone, so bisection is safe and exact enough. */
function betaInv(p: number, a: number, b: number): number {
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 200; i++) {
    const mid = (lo + hi) / 2;
    if (incompleteBeta(mid, a, b) < p) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

/**
 * Exact two-sided Clopper-Pearson interval for k successes in n trials.
 *
 * The k=0 and k=n edges use their closed forms directly: they are exact, and going
 * through the beta inverse there would only add numerical noise to the two cases a
 * benchmark reports most.
 */
export function clopperPearson(k: number, n: number, alpha = 0.05): Interval {
  if (n <= 0) return { point: 0, lower: 0, upper: 1, k, n };
  if (k < 0 || k > n) throw new Error(`clopperPearson: k=${k} out of range for n=${n}`);

  const point = k / n;
  const half = alpha / 2;

  // Both edges have exact closed forms, because I_x(n,1) = x^n. Using them avoids the
  // few parts-per-million of bisection error that the general path carries, and these
  // are the two cases a security benchmark reports most often - "we caught all of them"
  // and "we blocked none of the legitimate ones".
  if (k === 0) return { point, lower: 0, upper: 1 - Math.pow(half, 1 / n), k, n };
  if (k === n) return { point, lower: Math.pow(half, 1 / n), upper: 1, k, n };

  return { point, lower: betaInv(half, k, n - k + 1), upper: betaInv(1 - half, k + 1, n - k), k, n };
}

/** Smallest n such that observing zero failures bounds the rate below `target`. */
export function samplesNeeded(target: number, alpha = 0.05): number {
  if (target <= 0 || target >= 1) throw new Error(`samplesNeeded: target must be in (0,1)`);
  return Math.ceil(Math.log(alpha / 2) / Math.log(1 - target));
}

export const fmtInterval = (i: Interval, digits = 1): string =>
  `${(i.point * 100).toFixed(digits)}%  [${(i.lower * 100).toFixed(digits)}, ${(i.upper * 100).toFixed(digits)}]`;
