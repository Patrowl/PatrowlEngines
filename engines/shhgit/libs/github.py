'''
SHHGIT PatrOwl engine application

Copyright 2021 Leboncoin
Licensed under the Apache License
Written by Fabien Martinez <fabien.martinez+github@adevinta.com>
'''
import logging

from github import Github


def get_repositories(github_account, organization):
    """Retrieve repositories from a Github organization."""
    logger = logging.getLogger(__name__)
    try:
        repositories = github_account.get_organization(organization).get_repos()
    except Exception as e:
        logger.error(f'Unable to get repositories: {e}')
        return False
    return repositories


def get_github_repositories(github_account):
    """Retrieve repositories."""
    logger = logging.getLogger(__name__)
    github = Github(github_account['github_key'])
    if github_account['is_internal']:
        github = Github(
            base_url=github_account['base_url'],
            login_or_token=github_account['github_key']
        )
    raw_repositories = get_repositories(github, github_account['organization'])
    if raw_repositories is False:
        logger.error('Error while getting repositories.')
        return False
    repositories = []
    for raw_repository in raw_repositories:
        repositories.append({
            'id': raw_repository.id,
            'name': raw_repository.name,
            'clone_url': raw_repository.clone_url
        })
    return repositories
