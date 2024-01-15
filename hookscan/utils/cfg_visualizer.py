import subprocess
from hashlib import md5

import graphviz

from hookscan.components.contract import Contract


def shorten(filename):
    m = md5()
    m.update(filename.encode())
    return filename[:100] + "_" + m.digest().hex()


def generate_cfg(contract: Contract, path: str, render=False):
    node_attr = {"shape": "box"}
    if not path.endswith("/"):
        path += "/"
    functions = {
        "creation": list(contract.creation_functions_dict.values()) + [contract.creation],
        "runtime": list(contract.runtime_functions_dict.values()) + [contract.runtime],
    }
    filenames = []
    for step in ("creation", "runtime"):
        cur_path = path + str(step) + "/"

        for function in functions[step]:
            filename = f"{cur_path}{contract.yul_name}-{function.name}"
            args = "arguments: " + ", ".join([arg.name + ": " + arg.info_rvalue() for arg in function.arguments])
            rets = "return values: " + ", ".join(function.return_names)
            if len(filename) > 100:
                filename = shorten(filename)
            s = graphviz.Digraph("CFG", filename=f"{filename}.dot", node_attr=node_attr)
            filenames.append(f"{filename}.dot")
            s.attr(label="\n".join([function.name, args, rets]), labelloc="t")

            for bb in function.basic_blocks:
                bb_name = str(bb.id)
                s.node(
                    name=bb_name,
                    label=f"basic block id:{bb_name}\n\n" + r"\l".join([ins.info() for ins in bb.instructions]) + r"\l",
                )

                for predecessor in bb.predecessors:
                    s.edge(str(predecessor.id), bb_name)

            s.save()

    if render:
        subprocess.run(["dot", "-Tpdf", "-O"] + filenames)
