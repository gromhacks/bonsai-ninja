import asyncio
from storage import open_handle


# Direct use-after-close.
def use_after_close(f):
    f.close()
    return f.read()


# Conditional close on the error branch.
def conditional_close(f, fail):
    if fail:
        f.close()
    return f.read()


# Loop UAF: closing inside the loop leaves the rest of the loop dangling.
def loop_close_then_read(f, n):
    for i in range(n):
        if i == 0:
            f.close()
        f.read()


# Aliased binding: rename and read after the rename.
def aliased_close(f):
    g = f
    f.close()
    g.read()


# Cancel then result on an asyncio task.
async def cancel_then_result():
    task = asyncio.create_task(asyncio.sleep(0.1))
    task.cancel()
    return task.result()


def main():
    f = open_handle("/tmp/data.bin")
    use_after_close(f)
