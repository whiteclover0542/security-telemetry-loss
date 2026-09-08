# -*- coding: utf-8 -*-
"""stats.py 검증.

외부 통계 패키지를 쓰지 않고 직접 구현했으므로, 손으로 계산할 수 있는 값과
널리 공표된 임계값에 대조한다. 실행:

    python scripts/test_stats.py
"""
import math
import sys

import stats


FAILED = []


def check(name, got, want, tol=1e-6):
    ok = abs(got - want) <= tol
    print("%-52s got=%-22.10g want=%-14.10g %s" % (name, got, want, "OK" if ok else "FAIL"))
    if not ok:
        FAILED.append(name)


def check_list(name, got, want):
    ok = len(got) == len(want) and all(abs(a - b) < 1e-9 for a, b in zip(got, want))
    print("%-52s %s  %s" % (name, got, "OK" if ok else "FAIL (want %s)" % (want,)))
    if not ok:
        FAILED.append(name)


print("== 순위 매기기 (동순위는 평균 순위) ==")
check_list("ranks([10,20,20,30])", stats.ranks([10, 20, 20, 30]), [1, 2.5, 2.5, 4])
check_list("ranks([5,5,5])", stats.ranks([5, 5, 5]), [2, 2, 2])

print("\n== 백분위수 (선형보간) ==")
check("quantile([1,2,3,4], 0.5)", stats.quantile([1, 2, 3, 4], 0.5), 2.5)
check("quantile([1,2,3,4], 0.25)", stats.quantile([1, 2, 3, 4], 0.25), 1.75)
check("quantile([1,2,3,4,5], 0.75)", stats.quantile([1, 2, 3, 4, 5], 0.75), 4.0)

print("\n== t분포 ==")
# 자유도 1의 t분포는 표준 코시분포이므로 P(|T| > 1) = 0.5 (정확값)
check("t_two_sided_p(1, df=1)  [코시, 정확값 0.5]", stats.t_two_sided_p(1.0, 1), 0.5, 1e-9)
check("t_sf(0, df=10)", stats.t_sf(0.0, 10), 0.5, 1e-9)
# 자유도가 크면 정규분포에 수렴: P(|Z|>1.959964) = 0.05
check("t_two_sided_p(1.959964, df=100000)", stats.t_two_sided_p(1.959964, 100000), 0.05, 1e-4)

print("\n== 카이제곱 분포 (공표된 임계값) ==")
check("chi2_sf(3.8414588, df=1)", stats.chi2_sf(3.8414588, 1), 0.05, 1e-6)
check("chi2_sf(5.9914645, df=2)", stats.chi2_sf(5.9914645, 2), 0.05, 1e-6)
check("chi2_sf(7.8147279, df=3)", stats.chi2_sf(7.8147279, 3), 0.05, 1e-6)
check("chi2_sf(0, df=4)", stats.chi2_sf(0.0, 4), 1.0, 1e-12)

print("\n== Spearman 순위상관 ==")
rho, _ = stats.spearman([1, 2, 3, 4, 5], [10, 20, 30, 40, 50])
check("완전 단조증가 -> rho = 1", rho, 1.0, 1e-12)
rho, _ = stats.spearman([1, 2, 3, 4, 5], [50, 40, 30, 20, 10])
check("완전 단조감소 -> rho = -1", rho, -1.0, 1e-12)
# 손계산: 순위 x=[1,2,3,4], 순위 y=[1.5,1.5,3.5,3.5]
#         Sxy=4, Sxx=5, Syy=4  ->  rho = 4/sqrt(20) = 0.8944271910
rho, p = stats.spearman([1, 2, 3, 4], [1, 1, 2, 2])
check("동순위 포함 손계산 4/sqrt(20)", rho, 4.0 / math.sqrt(20.0), 1e-12)

print("\n== Kruskal-Wallis ==")
# 손계산: groups [[1,2,3],[4,5,6]], R1=6, R2=15, n=6
#         H = 12/(6*7)*(36/3 + 225/3) - 3*7 = 3.857142857, 동순위 없음
h, df, p = stats.kruskal_wallis([[1, 2, 3], [4, 5, 6]])
check("H (동순위 없음, 손계산 27/7)", h, 27.0 / 7.0, 1e-12)
check("df", df, 1, 0)
# 손계산: groups [[1,1],[2,2]] -> H_raw = 2.4, 보정계수 0.8 -> H = 3.0
h, df, p = stats.kruskal_wallis([[1, 1], [2, 2]])
check("H (동순위 보정, 손계산 2.4/0.8)", h, 3.0, 1e-12)

print("\n== 기술통계 ==")
d = stats.describe([2, 4, 4, 4, 5, 5, 7, 9])
check("mean", d["mean"], 5.0)
check("sd (표본표준편차)", d["sd"], math.sqrt(32.0 / 7.0), 1e-12)
check("median", d["median"], 4.5)

print("\n== 부트스트랩 (같은 seed면 같은 결과) ==")
x = list(range(50))
y = [v * 2 + (v % 7) for v in x]
a = stats.bootstrap_ci(x, y, lambda p, q: stats.spearman(p, q)[0], reps=200)
b = stats.bootstrap_ci(x, y, lambda p, q: stats.spearman(p, q)[0], reps=200)
print("%-52s %s == %s  %s" % ("재실행 시 동일한 신뢰구간", a, b, "OK" if a == b else "FAIL"))
if a != b:
    FAILED.append("bootstrap 재현성")

print("\n" + "=" * 70)
if FAILED:
    print("실패 %d건: %s" % (len(FAILED), ", ".join(FAILED)))
    sys.exit(1)
print("모든 검증 통과")
