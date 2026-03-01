# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
统一的日志配置模块

提供标准化的日志配置函数，确保项目中所有模块使用一致的日志格式。
"""

import logging
import os
from typing import Optional

log_file_name = "run_all_experiments.log"

def setup_logger(
    logger_name: str,
    log_level: int = logging.INFO,
    log_dir: Optional[str] = None
) -> logging.Logger:
    """
    配置并返回一个标准化的logger实例。
    
    Args:
        logger_name: Logger的名称，通常使用 __name__
        log_file_name: 日志文件名，如果为None则根据logger_name自动生成
        log_level: 日志级别，默认为DEBUG
        log_dir: 日志文件目录，如果为None则使用默认目录（项目根目录下的logs）
    
    Returns:
        配置好的Logger实例
    
    Example:
        >>> logger = setup_logger(__name__)
        >>> logger.info("This is a log message")
    """
    # 获取或创建logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    
    # 如果未指定log_dir，使用默认目录
    if log_dir is None:
        return logger
    else:
        # 确保指定的目录存在
        os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, log_file_name)
    
    # 创建标准格式化器
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # 配置文件handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # 配置控制台handler (显示在终端)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger(__name__, log_level=logging.INFO, log_dir=None)
