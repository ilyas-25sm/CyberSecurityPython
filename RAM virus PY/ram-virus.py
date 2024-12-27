import time
import os

def main():
    print("Этот процесс работает только в оперативной памяти.")
    print(f"PID процесса: {os.getpid()}")
    print("Начало работы...")
    try:
        while True:
            # Симуляция активности
            print("Работаю в оперативной памяти...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Процесс завершён.")

if __name__ == "__main__":
    main()
