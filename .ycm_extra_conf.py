import os

def Settings( **kwargs ):
  if kwargs[ 'language' ] == 'cfamily':
    return {
      'flags': ['-x', 'c++',
                '-std=c++17',
                '-D', 'WINDOWS=1',
                '-D', 'X86_64=1',
                '-I', 'src',
                '-I', 'third_party',
                '-I', 'C:\\git\\dynamorio\\build\\include',
                '-I', 'C:\\git\\dynamorio\\build\\ext\\include',
                ],
    }
