import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import org.json.JSONObject;
import java.util.regex.*;

public class Main {

    private static final String LOG_FILE_ENCODING = "UTF-8";
    private static final String OUTPUT_FILE_ENCODING = "UTF-8";

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        // получение необходимой информации
        System.out.println("Желаете ли задать временной период для анализа? (yes/no)");
        String userInput = scanner.nextLine().trim().toLowerCase();

        String inputLogFile, outputFile;
        Date startDate = null, endDate = null;

        if ("yes".equals(userInput)) {
            System.out.println("Введите начальную дату и время для анализа (формат: dd.MM.yyyy-HH.mm.ss):");
            String startDateString = scanner.nextLine().trim();
            System.out.println("Введите конечную дату и время для анализа (формат: dd.MM.yyyy-HH.mm.ss):");
            String endDateString = scanner.nextLine().trim();

            SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy-HH.mm.ss");

            try {
                startDate = dateFormat.parse(startDateString);
                endDate = dateFormat.parse(endDateString);
            } catch (ParseException e) {
                System.err.println("Ошибка парсинга даты. Используйте формат dd.MM.yyyy-HH.mm.ss");
                e.printStackTrace();
                return;
            }
        }

        System.out.println("Введите путь к входному log-файлу:");
        inputLogFile = scanner.nextLine().trim();

        System.out.println("Введите путь к выходному файлу:");
        outputFile = scanner.nextLine().trim();

        // Выполняем анализ логов с учетом временного периода, если он задан
        if (startDate != null && endDate != null) {
            analyzeLog(inputLogFile, outputFile, startDate, endDate);
        } else {
            analyzeLog(inputLogFile, outputFile);
        }

        System.out.println("Анализ завершен. Результаты сохранены в " + outputFile);
        scanner.close();
    }
    private static void analyzeLog(String inputLogFile, String outputFile, Date startDate, Date endDate) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(inputLogFile), LOG_FILE_ENCODING));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputFile), OUTPUT_FILE_ENCODING))) {
            String line;
            SimpleDateFormat logDateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

            // выражение для парсинга лог-строк
            Pattern logPattern = Pattern.compile("(\\d{4}/\\d{2}/\\d{2}) (\\d{2}:\\d{2}:\\d{2}) \\[([a-zA-Z]+)] (\\d+#\\d+): \\*(\\d+) (.+)$");

            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    Matcher matcher = logPattern.matcher(line);
                    if (matcher.matches()) {
                        try {
                            // извлекаем дату строки лог-файла
                            String logDateString = matcher.group(1) + " " + matcher.group(2);
                            Date logDate = logDateFormat.parse(logDateString);
                            // смотрим попадает ли дата диапазон
                            if (logDate.after(startDate) && logDate.before(endDate)) {
                                // проверка запроса на подозрительность
                                String logMessage = matcher.group(6);
                                if (isSuspiciousRequest(logMessage)) {
                                    // создаем json-объект
                                    JSONObject logEntry = new JSONObject();
                                    logEntry.put("date", matcher.group(1));
                                    logEntry.put("time", matcher.group(2));
                                    logEntry.put("level", matcher.group(3));
                                    logEntry.put("pid", matcher.group(4));
                                    logEntry.put("request_id", matcher.group(5));
                                    logEntry.put("message", logMessage);

                                    // записываем в выходной файл
                                    writer.write(logEntry.toString());
                                    writer.newLine();
                                }
                            }
                        } catch (ParseException e) {
                            System.err.println("Ошибка парсинга даты в строке: " + line);
                            e.printStackTrace();
                        }
                    } else {
                        System.err.println("Строка лога имеет недостаточное количество частей: " + line);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Ошибка чтения log-файла: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private static void analyzeLog(String inputLogFile, String outputFile) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(inputLogFile), LOG_FILE_ENCODING));
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputFile), OUTPUT_FILE_ENCODING))) {

            String line;

            // Регулярное выражение для парсинга лог-строк
            Pattern logPattern = Pattern.compile("(\\d{4}/\\d{2}/\\d{2}) (\\d{2}:\\d{2}:\\d{2}) \\[([a-zA-Z]+)] (\\d+#\\d+): \\*(\\d+) (.+)$");

            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    Matcher matcher = logPattern.matcher(line);
                    if (matcher.matches()) {
                        // проверка запроса на подозрительность
                        String logMessage = matcher.group(6);
                        if (isSuspiciousRequest(logMessage)) {
                            // создаем json-объект
                            JSONObject logEntry = new JSONObject();
                            logEntry.put("date", matcher.group(1));
                            logEntry.put("time", matcher.group(2));
                            logEntry.put("level", matcher.group(3));
                            logEntry.put("pid", matcher.group(4));
                            logEntry.put("request_id", matcher.group(5));
                            logEntry.put("message", logMessage);

                            // записываем в выходной файл
                            writer.write(logEntry.toString());
                            writer.newLine();
                        }
                    } else {
                        System.err.println("Строка лога имеет недостаточное количество частей: " + line);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Ошибка чтения log-файла: " + e.getMessage());
            e.printStackTrace();
        }
    }
    private static boolean isSuspiciousRequest(String line) {
        String[] notSuspiciousKeywords = {"/wwwbsuir/exploded", "/online/galleries", "/news", "/impuls", "/online/layouts",
                ".pdf", ".jpg", ".docx", ".pptx", ".doc", ".php", ".css", "/ru", "/en", "/online/showpage",
                ".png", ".PDF", ".xls", ".webp", ".svg", "/profkom", ".JPG", ".jfif", ".ppsx", ".xml", ".pps", ".JPG", ".jpeg",
                ".rtf", ".RTF", ".TXT", ".ppt", ".gif", ".htm", "one_rubric.", "index.", ".txt", "/musey", "/fksis", "/bel",
                "/kaf-ikt", "/sportclub", "/programmnyy-komitet", ".PNG", ".DOC", ".bmp", "yandex", "/rss?", "/ ", "/online/tnj2"};

        for (String keyword : notSuspiciousKeywords) {
            if (line.contains(keyword)) {
                return false;
            }
        }
        return true;
    }
}