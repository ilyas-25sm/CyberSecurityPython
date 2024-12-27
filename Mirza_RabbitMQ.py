import os
import psutil
import pika
import logging
import json
from PyQt5.QtCore import QThread, pyqtSignal

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, filename="rabbitmq_antivirus.log", filemode="a",
                    format="%(asctime)s - %(levelname)s - %(message)s")


class RabbitMQMonitorThread(QThread):
    error_signal = pyqtSignal(str)

    def __init__(self, host="localhost", queue="antivirus_queue"):
        """
        Инициализация потока для мониторинга RabbitMQ.

        Args:
            host (str): Хост RabbitMQ.
            queue (str): Имя очереди для мониторинга.
        """
        super().__init__()
        self.host = host
        self.queue = queue
        self.connection = None
        self.channel = None
        self.running = False

    def run(self):
        """
        Основной метод запуска RabbitMQ мониторинга.
        """
        try:
            logging.info(f"Connecting to RabbitMQ host: {self.host}, queue: {self.queue}")
            self.connection = pika.BlockingConnection(pika.ConnectionParameters(self.host))
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue=self.queue)

            def callback(ch, method, properties, body):
                """
                Callback-функция для обработки сообщений из очереди.

                Args:
                    ch: Канал RabbitMQ.
                    method: Метаданные сообщения.
                    properties: Свойства сообщения.
                    body: Тело сообщения.
                """
                try:
                    process_data = json.loads(body)
                    logging.info(f"Received process data: {process_data}")
                    if self.is_suspicious(process_data):
                        self.block_process(process_data['pid'])
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding message: {e}")
                except KeyError as e:
                    logging.error(f"Missing key in process data: {e}")

            self.running = True
            self.channel.basic_consume(queue=self.queue, on_message_callback=callback, auto_ack=True)

            logging.info("RabbitMQ monitoring started.")
            while self.running:
                self.connection.process_data_events(time_limit=1)

        except pika.exceptions.AMQPConnectionError as e:
            error_message = f"RabbitMQ connection error: {e}"
            logging.error(error_message)
            self.error_signal.emit(error_message)

        except Exception as e:
            error_message = f"Unexpected error in RabbitMQ monitor: {e}"
            logging.error(error_message)
            self.error_signal.emit(error_message)

        finally:
            self.close()

    @staticmethod
    def is_suspicious(process_data):
        """
        Эвристический анализ данных о процессах.

        Args:
            process_data (dict): Данные о процессе.

        Returns:
            bool: True, если процесс подозрительный, иначе False.
        """
        suspicious_keywords = ["malware", "virus", "trojan"]
        cpu_threshold = 80  # Уровень CPU для подозрения
        memory_threshold = 500  # Порог в МБ для использования памяти

        if any(keyword in process_data['name'].lower() for keyword in suspicious_keywords):
            logging.warning(f"Suspicious process name detected: {process_data['name']}")
            return True

        if process_data.get('cpu', 0) > cpu_threshold:
            logging.warning(f"High CPU usage detected: {process_data['cpu']}% for {process_data['name']}")
            return True

        if process_data.get('memory', 0) > memory_threshold:
            logging.warning(f"High memory usage detected: {process_data['memory']}MB for {process_data['name']}")
            return True

        return False

    @staticmethod
    def block_process(pid):
        """
        Завершение процесса с указанным PID.

        Args:
            pid (int): Идентификатор процесса.
        """
        try:
            if psutil.pid_exists(pid):
                os.kill(pid, 9)
                logging.info(f"Process {pid} terminated successfully.")
            else:
                logging.warning(f"Process {pid} does not exist.")
        except Exception as e:
            logging.error(f"Failed to terminate process {pid}: {e}")

    def close(self):
        """
        Закрытие соединения с RabbitMQ.
        """
        self.running = False
        if self.connection:
            try:
                self.connection.close()
                logging.info("Connection to RabbitMQ closed.")
            except Exception as e:
                logging.error(f"Error closing RabbitMQ connection: {e}")


# MAIN (Для тестирования)
if __name__ == "__main__":
    logging.info("=== Starting RabbitMQ Monitor Test ===")
    monitor = RabbitMQMonitorThread()
    monitor.start()
    try:
        while monitor.isRunning():
            pass
    except KeyboardInterrupt:
        logging.info("Stopping RabbitMQ monitor.")
        monitor.close()
