package org.example;

import java.util.HashSet;
import java.util.Set;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PseudoRandomeTest {
    public static void main(String[] args) {
        long a = 3, b = 2, c = 3, d = 4, m = 6500000L, seed = 1;
        PseudoRandomе generator = new PseudoRandomе(a, b, c, d, m, seed);

        int count = 10000;
        long[] randomNumbers = generator.nextRange(count);

        testUniformity(randomNumbers, m);

        testAutocorrelation(randomNumbers);

        testIndependence(randomNumbers, m);
        try {
            PseudoRandomе r = new PseudoRandomе(a,b,c,d,m, seed);
            Set<Long> arrayList = new HashSet<>();
            long len = 0;
            try {
                while (true) {
                    long temp = r.nextRangeWithMemory(1)[0];
                    if (arrayList.contains(temp)) {
                        System.out.println("Длинна - " + len);
                        break;
                    } else {
                        arrayList.add(temp);
                        len++;
                    }
                    if (len % 10000 == 0) {
                        System.out.println("Пройден рубеж - " + len);
                    }
                }
            } catch (Exception e) {
                System.out.println("Достигнут лимит массива: " + e);
            }
        }catch (OutOfMemoryError er){
            System.out.println("А всё, памяти нема");
        }
    }

    public static void testUniformity(long[] randomNumbers, long m) {
        System.out.println("Тест на равномерное распределение:");
        Map<Long, Integer> histogram = new HashMap<>();

        for (long number : randomNumbers) {
            histogram.put(number, histogram.getOrDefault(number, 0) + 1);
        }

        for (Map.Entry<Long, Integer> entry : histogram.entrySet()) {
            System.out.println("Значение: " + entry.getKey() + " Частота: " + entry.getValue());
        }

    }

    public static void testAutocorrelation(long[] randomNumbers) {
        System.out.println("\nТест на автокорреляцию:");
        int n = randomNumbers.length;
        double mean = Arrays.stream(randomNumbers).average().orElse(0);
        double autocorrelation = 0.0;

        for (int i = 0; i < n - 1; i++) {
            autocorrelation += (randomNumbers[i] - mean) * (randomNumbers[i + 1] - mean);
        }

        autocorrelation /= (n - 1);

        System.out.println("Коэффициент автокорреляции: " + autocorrelation);
    }

    public static void testIndependence(long[] randomNumbers, long m) {
        System.out.println("\nТест на независимость (Хи-квадрат):");
        int n = randomNumbers.length;
        double expectedFrequency = (double) n / m;
        double chiSquare = 0.0;

        Map<Long, Integer> frequencies = new HashMap<>();
        for (long number : randomNumbers) {
            frequencies.put(number, frequencies.getOrDefault(number, 0) + 1);
        }

        for (Map.Entry<Long, Integer> entry : frequencies.entrySet()) {
            double observed = entry.getValue();
            chiSquare += Math.pow(observed - expectedFrequency, 2) / expectedFrequency;
        }

        System.out.println("Значение Хи-квадрат: " + chiSquare);
    }
}

class PseudoRandomе {
    private final long a, b, c, d, m;
    private long seed;

    public PseudoRandomе(long a, long b, long c, long d, long m, long seed) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.d = d;
        this.m = m;
        this.seed = seed;
    }

    public long pow(long x, long pow) {
        return (long) (Math.pow(x, pow));
    }

    private long nextRandom(long x) {
        return (a * pow(x, 3) + b * pow(x, 2) + c * x + d) % m;
    }

    public long[] nextRange(int count) {
        long[] range = new long[count];
        range[0] = seed;
        for (int i = 1; i < count; i++) {
            range[i] = nextRandom(range[i - 1]);
        }
        return range;
    }

    public long[] nextRangeWithMemory(int count) {
        long[] range = new long[count + 1];
        range[0] = seed;
        for (int i = 1; i <= count; i++) {
            range[i] = nextRandom(range[i - 1]);
        }
        seed = range[count];
        return range;
    }

}
