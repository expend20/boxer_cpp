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
                '-I', '',
                '-I', 'build/third_party/obj/wkit/include',
                '-I', 'build/_deps/googletest-src/googletest/include'
                ],
    }   
