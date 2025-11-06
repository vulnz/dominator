"""
Git exposure payload collection
"""

class GitPayloads:
    """Git exposure payload collection"""
    
    @staticmethod
    def get_git_paths():
        """Get common git paths to test"""
        return [
            '.git/',
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/logs/HEAD',
            '.git/logs/refs/heads/master',
            '.git/logs/refs/heads/main',
            '.git/logs/refs/heads/develop',
            '.git/logs/refs/remotes/origin/master',
            '.git/logs/refs/remotes/origin/main',
            '.git/refs/heads/master',
            '.git/refs/heads/main',
            '.git/refs/heads/develop',
            '.git/refs/remotes/origin/master',
            '.git/refs/remotes/origin/main',
            '.git/objects/',
            '.git/info/refs',
            '.git/description',
            '.git/hooks/',
            '.git/packed-refs',
            '.git/COMMIT_EDITMSG',
            '.git/FETCH_HEAD',
            '.git/ORIG_HEAD',
            '.git/refs/tags/',
            '.git/info/exclude'
        ]
    
    @staticmethod
    def get_git_object_paths():
        """Get git object paths (these are usually harder to guess)"""
        # Common object hashes that might exist
        common_objects = [
            'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391',  # Empty file
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',  # Empty string SHA1
            '4b825dc642cb6eb9a060e54bf8d69288fbee4904',  # Empty tree
            'b25c15b81fae06e1c55946ac6270bfdb293870e8',  # Common initial commit
        ]
        
        object_paths = []
        for obj_hash in common_objects:
            # Git objects are stored as .git/objects/XX/XXXXXXX...
            prefix = obj_hash[:2]
            suffix = obj_hash[2:]
            object_paths.append(f'.git/objects/{prefix}/{suffix}')
        
        return object_paths
    
    @staticmethod
    def get_all_git_payloads():
        """Get all git-related paths to test"""
        return GitPayloads.get_git_paths() + GitPayloads.get_git_object_paths()
    
    @staticmethod
    def get_git_directory_variations():
        """Get variations of .git directory path"""
        return [
            '.git',
            '.git/',
            '/.git',
            '/.git/',
            '.git%2f',
            '.git%5c',
            '%2egit/',
            '%2egit%2f',
            'git/',
            '.Git/',
            '.GIT/',
            '.git.bak/',
            '.git.old/',
            'git.tar.gz',
            'git.zip',
            '.git.tar.gz',
            '.git.zip'
        ]
