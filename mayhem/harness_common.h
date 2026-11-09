// Shared setup for the SoftEther VPN libFuzzer harnesses: initialise Mayaqua + Cedar once.
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#include <Mayaqua/Mayaqua.h>
#include <Mayaqua/Memory.h>
#include <Mayaqua/Str.h>
#include <Mayaqua/Internat.h>
#include <Mayaqua/Pack.h>
#include <Mayaqua/Cfg.h>
#include <Mayaqua/TcpIp.h>
#include <Mayaqua/Network.h>
#include <Cedar/Cedar.h>
#include <Cedar/Proto_IPsec.h>
#include <Cedar/Proto_OpenVPN.h>
#include <Cedar/Proto_IkePacket.h>
#include <Cedar/Proto_L2TP.h>
#include <Cedar/Proto_PPP.h>
#include <Cedar/Proto_SSTP.h>

#include <stddef.h>
#include <stdint.h>

#ifndef MAYHEM_NO_FUZZER_INIT
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static char *av[2];

	// Mayaqua locates hamcore.se2 and checks that the executable exists via argv[0]
	av[0] = (*argc >= 1) ? (*argv)[0] : NULL;
	InitMayaqua(false, false, 1, av);
	InitCedar();
	return 0;
}
#endif

#endif
