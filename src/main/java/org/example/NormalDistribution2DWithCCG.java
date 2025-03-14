package org.example;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import javax.swing.*;

class PseudoRandom {
    private final long a, b, c, d, m;
    private long seed;

    public PseudoRandom(long a, long b, long c, long d, long m, long seed) {
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

    public long next() {
        seed = nextRandom(seed);
        return seed;
    }
}

public class NormalDistribution2DWithCCG extends JFrame {

    private PseudoRandom generator;

    public NormalDistribution2DWithCCG(String title, PseudoRandom generator) {
        super(title);
        this.generator = generator;

        // Создаем dataset с двумерным нормальным распределением
        XYSeries series = new XYSeries("Normal Distribution using CCG");

        double meanX = 0;
        double meanY = 0;
        double stddevX = 1;
        double stddevY = 1;

        // Генерируем точки для двумерного нормального распределения
        for (int i = 0; i < 1000; i++) {
            // Используем преобразование Бокса-Мюллера для получения нормального распределения из равномерного
            double[] gaussian = generateGaussian();
            double x = meanX + stddevX * gaussian[0];
            double y = meanY + stddevY * gaussian[1];
            series.add(x, y);
        }

        XYSeriesCollection dataset = new XYSeriesCollection();
        dataset.addSeries(series);

        // Создаем график
        JFreeChart chart = ChartFactory.createScatterPlot(
                "2D Normal Distribution using CCG",
                "X", "Y", dataset,
                PlotOrientation.VERTICAL,
                true, true, false);

        // Показ графика в окне
        ChartPanel panel = new ChartPanel(chart);
        setContentPane(panel);
    }

    private double[] generateGaussian() {
        // Получаем два случайных числа от 0 до 1 с помощью Кубического конгруэнтного генератора
        double u1 = (generator.next() % 10000) / 10000.0;  // Приводим к диапазону [0, 1]
        double u2 = (generator.next() % 10000) / 10000.0;

        // Преобразование Бокса-Мюллера для получения нормально распределенных значений
        double z0 = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        double z1 = Math.sqrt(-2.0 * Math.log(u1)) * Math.sin(2 * Math.PI * u2);
        return new double[]{z0, z1};
    }

    public static void main(String[] args) {
        // Инициализация Кубического конгруэнтного генератора
        PseudoRandom ccg = new PseudoRandom(78451258, 874512, 785421, 3, Long.MAX_VALUE, 42);

        SwingUtilities.invokeLater(() -> {
            NormalDistribution2DWithCCG example = new NormalDistribution2DWithCCG("2D Normal Distribution with CCG", ccg);
            example.setSize(800, 600);
            example.setLocationRelativeTo(null);
            example.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
            example.setVisible(true);
        });
    }
}

