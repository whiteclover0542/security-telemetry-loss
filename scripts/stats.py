# -*- coding: utf-8 -*-
"""표준 라이브러리만으로 구현한 통계 함수.

외부 패키지(scipy, numpy, pandas)를 쓰지 않는다. 재현하는 사람이 아무것도
설치하지 않고 python 하나로 실행할 수 있게 하기 위해서다.

구현한 것
    ranks               동순위를 평균 순위로 처리하는 순위 매기기
    spearman            Spearman 순위상관계수와 양측 p값
    kruskal_wallis      Kruskal-Wallis H 검정 (동순위 보정 포함)
    bootstrap_ci        비복원이 아닌 복원추출 기반 백분위수 신뢰구간
    describe            n, 평균, 표준편차, 최소, 사분위수, 최대

검증: 이 모듈의 함수들은 scripts/test_stats.py 에서 손으로 계산한 값 및
공개된 교과서 예제와 대조한다.
"""
import math
import random


# ---------------------------------------------------------------- 분포 함수
def _betacf(a, b, x, itmax=200, eps=3e-16):
    """정규화 불완전 베타 함수의 연분수 전개 (Numerical Recipes 방식)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, itmax + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a, b, x):
    """정규화 불완전 베타 함수 I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def t_sf(t, df):
    """자유도 df인 t분포의 우측 꼬리 확률 P(T > t)."""
    x = df / (df + t * t)
    p = 0.5 * betainc(df / 2.0, 0.5, x)
    return p if t > 0 else 1.0 - p


def t_two_sided_p(t, df):
    return 2.0 * t_sf(abs(t), df)


def _gser(a, x, itmax=500, eps=3e-16):
    ap, s, delta = a, 1.0 / a, 1.0 / a
    for _ in range(itmax):
        ap += 1.0
        delta *= x / ap
        s += delta
        if abs(delta) < abs(s) * eps:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gcf(a, x, itmax=500, eps=3e-16):
    tiny = 1e-300
    b, c = x + 1.0 - a, 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, itmax + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_sf(x, df):
    """카이제곱 분포의 우측 꼬리 확률 P(X > x)."""
    if x <= 0:
        return 1.0
    a = df / 2.0
    if x < a + 1.0:
        return 1.0 - _gser(a, x / 2.0)
    return _gcf(a, x / 2.0)


# ---------------------------------------------------------------- 순위·상관
def ranks(values):
    """동순위를 평균 순위로 매긴다. 1부터 시작."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            out[order[k]] = avg
        i = j + 1
    return out


def pearson(x, y):
    n = len(x)
    mx = sum(x) / n
    my = sum(y) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    if sxx == 0 or syy == 0:
        return float("nan")
    return sxy / math.sqrt(sxx * syy)


def spearman(x, y):
    """Spearman 순위상관계수와 양측 p값. 동순위는 평균 순위로 처리한다.

    p값은 t = r * sqrt((n-2)/(1-r^2)) 를 자유도 n-2의 t분포에 대입해 구한다.
    """
    if len(x) != len(y):
        raise ValueError("길이가 다르다")
    n = len(x)
    if n < 3:
        raise ValueError("표본이 너무 적다")
    rho = pearson(ranks(x), ranks(y))
    if rho != rho:  # nan
        return rho, float("nan")
    if abs(rho) >= 1.0:
        return rho, 0.0
    t = rho * math.sqrt((n - 2) / (1.0 - rho * rho))
    return rho, t_two_sided_p(t, n - 2)


def kruskal_wallis(groups):
    """Kruskal-Wallis H 검정. groups는 리스트의 리스트. 동순위 보정 포함.

    반환: (H, 자유도, p값)
    """
    groups = [g for g in groups if len(g) > 0]
    if len(groups) < 2:
        raise ValueError("집단이 2개 미만이다")
    pooled = [v for g in groups for v in g]
    n = len(pooled)
    r = ranks(pooled)

    # 동순위 보정계수
    counts = {}
    for v in pooled:
        counts[v] = counts.get(v, 0) + 1
    ties = sum(c ** 3 - c for c in counts.values() if c > 1)
    correction = 1.0 - ties / float(n ** 3 - n) if n > 1 else 1.0

    h = 0.0
    idx = 0
    for g in groups:
        rsum = sum(r[idx:idx + len(g)])
        h += rsum * rsum / len(g)
        idx += len(g)
    h = 12.0 / (n * (n + 1)) * h - 3.0 * (n + 1)
    if correction > 0:
        h /= correction
    df = len(groups) - 1
    return h, df, chi2_sf(h, df)


# ---------------------------------------------------------------- 기술통계
def quantile(sorted_values, q):
    """선형보간 백분위수 (numpy 기본 방식과 동일)."""
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    pos = (len(sorted_values) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_values[lo])
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def describe(values):
    v = sorted(values)
    n = len(v)
    mean = sum(v) / n
    var = sum((x - mean) ** 2 for x in v) / (n - 1) if n > 1 else 0.0
    return {
        "n": n,
        "mean": mean,
        "sd": math.sqrt(var),
        "min": v[0],
        "q1": quantile(v, 0.25),
        "median": quantile(v, 0.5),
        "q3": quantile(v, 0.75),
        "max": v[-1],
    }


def bootstrap_ci(x, y, stat, reps=5000, alpha=0.05, seed=20260908):
    """쌍(x[i], y[i])을 복원추출해 stat의 백분위수 신뢰구간을 구한다."""
    rng = random.Random(seed)
    n = len(x)
    vals = []
    for _ in range(reps):
        idx = [rng.randrange(n) for _ in range(n)]
        bx = [x[i] for i in idx]
        by = [y[i] for i in idx]
        try:
            s = stat(bx, by)
        except Exception:
            continue
        if s == s:
            vals.append(s)
    vals.sort()
    return quantile(vals, alpha / 2.0), quantile(vals, 1.0 - alpha / 2.0)
