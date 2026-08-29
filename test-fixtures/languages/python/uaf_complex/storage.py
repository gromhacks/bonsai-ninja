def open_handle(path):
    return open(path, "rb")


def write_then_close(f, data):
    f.write(data)
    f.close()


def cancel_then_check(task):
    task.cancel()
    return task.result()
