from source.monitor.file_monitor import monitor_directory

def main():
    print("\033[1m" + "Download Security Agent" + "\033[0m")
    print("\n"+"Status: Running")

    monitor_directory("samples/test_downloads")


if __name__ == "__main__":
    main()