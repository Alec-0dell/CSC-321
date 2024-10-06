import matplotlib.pyplot as plt

def plot_rsa_results(results):
    key_sizes = [512, 1024, 2048, 3072, 4096, 7680, 15360]
    sign_s = results['sign']
    verify_s = results['verify']

    plt.plot(key_sizes, sign_s, label='RSA Sign', marker='o')
    plt.plot(key_sizes, verify_s, label='RSA Verify', marker='o')

    plt.xlabel('RSA Key Size (bits)')
    plt.ylabel('Throughput (operations/s)')
    plt.title('RSA Performance: Throughput vs Key Size')
    plt.legend()
    
    plt.yscale('log')#optional log scale 

    plt.savefig('rsa_performance.png')
    plt.show()
    
def plot_aes_results(results):
    key_sizes = [16, 64, 256, 1024, 8192, 16384]
    aes128 = results['aes-128-cbc']
    aes192 = results['aes-192-cbc']
    aes256 = results['aes-256-cbc']

    plt.plot(key_sizes, aes128, label='AES 128', marker='o')
    plt.plot(key_sizes, aes192, label='AES 192', marker='o')
    plt.plot(key_sizes, aes256, label='AES 256', marker='o')

    plt.xlabel('AES Key Size (bits)')
    plt.ylabel('Throughput (operations/s)')
    plt.title('AES Performance: Throughput vs Key Size')
    plt.legend()
    
    plt.yscale('log') #optional log scale 

    plt.savefig('aes_performance.png')
    plt.show()

# RSA data
rsa_results = {
    'sign': [57996.0, 11818.4, 1901.1, 655.0, 300.4, 36.8, 6.8],
    'verify': [615716.7, 238839.1, 73356.2, 35748.2, 20917.5, 6075.9, 1514.9],
    'encr': [536608.6, 221452.0, 72206.9, 35131.0, 20476.3, 5988.0, 1537.9],
    'decr': [46755.9, 11118.1, 1864.9, 655.4, 300.3, 36.9, 6.8]
}

aes_results ={
    'aes-128-cbc': [76925942, 25093380, 6934898.67, 1770772.91, 222539, 109663],
    'aes-192-cbc': [68381305.33, 21751423.67, 5800049.66, 1483066.67, 187123.08, 93357.86],
    'aes-256-cbc': [58662766.55, 18801033.58, 5043626.85, 1272108.11, 160796.33, 80660.20],
}

plot_rsa_results(rsa_results)
plot_aes_results(aes_results)
