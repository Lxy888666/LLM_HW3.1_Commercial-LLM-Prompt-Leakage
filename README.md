# 实验材料说明

本目录收录本次提示词安全实验的报告、测试脚本和结果文件。

- `LLM_HW3.1_商业大模型提示词泄露_实验报告.md`：实验报告。
- `run_experiment.py`：对三个模型运行测试的脚本。
- `experiment_results.csv`：便于查看的测试记录，共 54 条。
- `experiment_outputs.jsonl`：对应的结构化记录，共 54 条。
- `requirements.txt`：脚本所需的 Python 依赖。

运行脚本需要 Python 3.9 或更新版本，并安装 `requirements.txt` 中的依赖。运行前需在本机设置 `DEEPSEEK_API_KEY`、`GLM_API_KEY` 和 `QWEN_API_KEY` 环境变量。不要把密钥写入代码或提交到仓库。

脚本会重新请求模型，并覆盖 CSV 和 JSONL 文件。当前结果中，每个模型有 15 条攻击测试和 3 条正常任务测试，共 54 条记录；多轮测试包含首轮和续问，因此实际发起 63 次请求。结果文件未单独保存多轮测试的首轮回复。
