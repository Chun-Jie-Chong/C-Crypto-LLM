from scipy import stats
import numpy as np

# Complexity
data1 = [7, 9, 65]
data2 = [12, 8, 37]

# Complexity per loc
# data1 = [0.04, 0.08, 0.33]
# data2 = [0.07, 0.07, 0.06]

# Perform t-test
t_stat, p_value = stats.ttest_ind(data1, data2)

print(f"T-statistic: {t_stat}")
print(f"P-value: {p_value}")
print(f"Mean of ChatGPT-4o: {np.mean(data1)}")
print(f"Mean of Human: {np.mean(data2)}")
print(f'Median of ChatGPT-4o: {np.median(data1)}')
print(f'Median of Human: {np.median(data2)}')
print(f'Geometric mean of ChatGPT-4o: {stats.gmean(data1)}')
print(f'Geometric mean of Human: {stats.gmean(data2)}')
print(f'Trimmed mean of ChatGPT-4o: {stats.trim_mean(data1, 0.05)}')
print(f'Trimmed mean of Human: {stats.trim_mean(data2, 0.05)}')
