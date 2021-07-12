from pathlib import Path
import logging
import hashlib
import shutil

import git

from .sast_git_leaks import sast_git_leaks
from .sast_git_leaks.config import variables


def clone_repository(logger, clone_url, repository_name, token, path):
    repository_path = path / f'{repository_name}_{hashlib.md5(clone_url.encode("utf-8")).hexdigest()}'
    logger.info(f'{repository_path = }')
    if repository_path.exists():
        logger.error(f'Unable to clone {clone_url}: Path {repository_path.absolute()} already exists')
        return False
        try:
            shutil.rmtree(repository_path)
        except Exception as e:
            logger.error(f'Unable to remove {repository_path.absolute()}: {e}')
    url = f'https://{token}@{clone_url.split("https://")[1]}'
    logger.info(f'Cloning repository {clone_url} in {repository_path}')
    try:
        git.Repo.clone_from(url, str(repository_path.absolute()))
    except Exception as e:
        logger.error(f'Unable to clone {clone_url}: {e}')
        return False
    return repository_path


def get_leaks_from_repository(logger, path, output):
    if not path.exists():
        logger.error(f'Unable to find repository path {path}')
        return False
    leaks = sast_git_leaks.process(
        logger,
        path,
        str(output.absolute()),
        variables,
        tools='shhgit'
    )
    if leaks is False:
        logger.error(f'Unable to get leaks from repository {path}')
    return leaks
