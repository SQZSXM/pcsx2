// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "microVU.h"
#include "VifCap.h"

#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace
{
struct VifCapBlockInfo
{
	u32 cycles;
	u32 count;
};
std::unordered_map<u32, VifCapBlockInfo> s_vifcap_blocks;

// vifcap: per-instruction watch on VU1 memory windows.  Changes are logged by
// vifcap_log_insn() and attributed to the instruction that caused them, which is
// the only way to see mid-block memory state (A's block hashes cannot).
//
// Default: the two XGKICK packet buffers of the analysed game, scanning only the
// instructions inside its vertex loop (pc range) so the cost stays negligible.
// Override with the environment variable
//     VIFCAP_WATCH="pc_lo:pc_hi:addr_lo:len[:addr_lo:len...]"
// (decimal or 0x-prefixed); a single window is supported per override for now.
constexpr u32 kVifcapWatchMaxLen = 0x1000;
struct VifCapWatchWindow
{
	u32 base;
	u32 len;
};
VifCapWatchWindow s_vifcap_watch[4] = {{0x2280, 0x400}, {0x2FC0, 0x340}, {0, 0}, {0, 0}};
u32 s_vifcap_watch_count = 2;
u32 s_vifcap_watch_pc_lo = 0x1500;
u32 s_vifcap_watch_pc_hi = 0x2B00;
u8 s_vifcap_watch_shadow[4][kVifcapWatchMaxLen];
bool s_vifcap_watch_valid = false;
bool s_vifcap_watch_cfg = false;
u32 s_vifcap_watch_prev_pc = 0;
} // namespace

// vifcap: effective address of the last LQ/LQI/LQD (set by emitted code, turned
// into a REC_MEMREAD by the next vifcap_log_insn call).
namespace vifcap
{
uint32_t g_vifcap_ldaddr = 0xFFFFFFFFu;
}

// Called when the capture opens: drop all compiled VU1 code so every block is
// recompiled with the logging hooks, while keeping the pipeline state intact.
void vifcap_purge_vu1_code()
{
	const microRegInfo saved = microVU1.prog.lpState;
	mVUreset(microVU1, false);
	microVU1.prog.lpState = saved;
	// vifcap: seed the XGKICK transfer state machine.  A packet transfer may be
	// pending across the capture start (the emulator was already running), and
	// without it the replay cannot tell where the next packet begins.  The
	// CHECK_XGKICKHACK gamefix picks between the delayed state machine and the
	// one-shot transfer path, so it is recorded too.
	vifcap::XgKickState(VU1.xgkickenable, VU1.xgkickaddr, VU1.xgkicksizeremaining,
	                    VU1.xgkickcyclecount, VU1.xgkickdiff, VU1.xgkickendpacket,
	                    EmuConfig.Gamefixes.XgKickHack ? 1u : 0u,
	                    (u32)VU1.xgkicklastcycle,
	                    microVU1.prog.lpState.xgkick,
	                    microVU1.prog.lpState.xgkickcycles,
	                    microVU1.VIxgkick);
	s_vifcap_watch_valid = false;
}

// Called from JIT-emitted code right before a one-shot XGKICK transfer: remember
// which VU instruction performed it (compile-time pc) and the cycle counter.
void vifcap_log_kickinfo(u32 pc)
{
	if (!vifcap::Enabled())
		return;
	vifcap::KickInfo(pc, microVU1.cycles);
}

// Called at compile time (plain C++ call): remember each block's cost.
void vifcap_record_block(u32 pc, u32 cycles, u32 count)
{
	s_vifcap_blocks[pc] = {cycles, count};
}

// Parse VIFCAP_WATCH once: "pc_lo:pc_hi:addr_lo:len[:addr_lo:len...]".
static void vifcap_watch_config()
{
	s_vifcap_watch_cfg = true;
	const char* env = std::getenv("VIFCAP_WATCH");
	if (!env || !*env)
		return;

	std::vector<u32> vals;
	const char* p = env;
	while (*p)
	{
		char* end = nullptr;
		const unsigned long v = std::strtoul(p, &end, 0);
		if (end == p)
			break;
		vals.push_back(static_cast<u32>(v));
		p = end;
		while (*p == ':' || *p == ',')
			++p;
	}
	if (vals.size() < 4)
		return;

	s_vifcap_watch_pc_lo = vals[0];
	s_vifcap_watch_pc_hi = vals[1];
	s_vifcap_watch_count = 0;
	for (size_t i = 2; i + 1 < vals.size() && s_vifcap_watch_count < 4; i += 2)
	{
		const u32 base = vals[i] & 0x3FFF;
		u32 len = vals[i + 1] & ~3u;
		if (!len)
			continue;
		if (len > kVifcapWatchMaxLen)
			len = kVifcapWatchMaxLen;
		s_vifcap_watch[s_vifcap_watch_count].base = base;
		s_vifcap_watch[s_vifcap_watch_count].len = len;
		++s_vifcap_watch_count;
	}
}

// Called from JIT-emitted code before every instruction (capped).
void vifcap_log_insn(u32 pc)
{
	static u32 logged = 0;
	if (!vifcap::Enabled())
		return;

	if (!s_vifcap_watch_cfg)
		vifcap_watch_config();

	// the previous instruction's LQ/LQI/LQD effective address (if any)
	if (vifcap::g_vifcap_ldaddr != 0xFFFFFFFFu)
	{
		u32 data[4];
		const u32 a = vifcap::g_vifcap_ldaddr & 0x3FFF;
		for (u32 k = 0; k < 4; k++)
		{
			u32 v;
			memcpy(&v, VU1.Mem + ((a + k * 4) & 0x3FFC), 4);
			data[k] = v;
		}
		vifcap::MemRead(s_vifcap_watch_prev_pc, a, data);
		vifcap::g_vifcap_ldaddr = 0xFFFFFFFFu;
	}

	const bool in_range = (pc >= s_vifcap_watch_pc_lo && pc <= s_vifcap_watch_pc_hi);
	if (in_range)
	{
		u32 addr[64];
		u32 value[64];
		u32 n = 0;
		if (!s_vifcap_watch_valid)
		{
			for (u32 w = 0; w < s_vifcap_watch_count; w++)
				memcpy(s_vifcap_watch_shadow[w], VU1.Mem + s_vifcap_watch[w].base,
				       s_vifcap_watch[w].len);
			s_vifcap_watch_valid = true;
		}
		for (u32 w = 0; w < s_vifcap_watch_count && n < 64; w++)
		{
			const u32 base = s_vifcap_watch[w].base;
			const u32 len = s_vifcap_watch[w].len;
			for (u32 off = 0; off < len && n < 64; off += 4)
			{
				u32 v;
				memcpy(&v, VU1.Mem + base + off, 4);
				u32 old;
				memcpy(&old, s_vifcap_watch_shadow[w] + off, 4);
				if (v != old)
				{
					addr[n] = base + off;
					value[n] = v;
					memcpy(s_vifcap_watch_shadow[w] + off, &v, 4);
					++n;
				}
			}
		}
		if (n)
			vifcap::MemWatch(s_vifcap_watch_prev_pc, addr, value, n);
		s_vifcap_watch_prev_pc = pc;
	}
	else
	{
		// re-seed the shadows when the next watched instruction comes around
		s_vifcap_watch_valid = false;
	}

	if (logged >= 500000)
		return;
	++logged;
	vifcap::Insn(pc);
}

// Called at every VU1 microVU batch entry: the 16 KB VU1 data memory is only
// otherwise dumped at MSCAL, so resync it here with a diff against a shadow
// copy (a full dump per batch would make the capture explode).
namespace
{
u8 s_vifcap_memshadow[0x4000];
bool s_vifcap_memshadow_valid = false;
} // namespace

void vifcap_vu1_mem_sync_reset()
{
	s_vifcap_memshadow_valid = false;
}

void vifcap_vu1_mem_sync()
{
	if (!vifcap::Enabled())
	{
		s_vifcap_memshadow_valid = false;
		return;
	}
	if (!s_vifcap_memshadow_valid)
	{
		vifcap::MemSync(0, VU1.Mem, 0x4000);
		memcpy(s_vifcap_memshadow, VU1.Mem, 0x4000);
		s_vifcap_memshadow_valid = true;
		return;
	}

	u32 changed = 0;
	for (u32 i = 0; i < 0x4000; i++)
		changed += (VU1.Mem[i] != s_vifcap_memshadow[i]);

	if (changed > 0x1000)
	{
		// too fragmented for ranges, just resync the whole thing
		vifcap::MemSync(0, VU1.Mem, 0x4000);
	}
	else
	{
		u32 i = 0;
		while (i < 0x4000)
		{
			if (VU1.Mem[i] == s_vifcap_memshadow[i])
			{
				i++;
				continue;
			}
			u32 start = i;
			u32 last = i;
			while (i < 0x4000 && (i - last) <= 64)
			{
				if (VU1.Mem[i] != s_vifcap_memshadow[i])
					last = i;
				i++;
			}
			const u32 len = last + 1 - start;
			vifcap::MemSync(start, VU1.Mem + start, len);
		}
	}
	memcpy(s_vifcap_memshadow, VU1.Mem, 0x4000);
}

// Called from JIT-emitted code at every block entry (xFastCall supports 2 args total).
void vifcap_log_block(u32 pc)
{
	if (!vifcap::Enabled())
		return;
	const auto it = s_vifcap_blocks.find(pc);
	if (it != s_vifcap_blocks.end())
	{
		vifcap::Block(pc, it->second.cycles, it->second.count, VU1.VI[2].UL & 0xFFFF, VU1.VI[3].UL & 0xFFFF, VU1.VI[12].UL & 0xFFFF, VU1.macflag, VU1.statusflag);
		{
			// vifcap: microVU keeps its live flags in microVU1.{mac,clip,stat}Flag[4]
			// (the JIT writes those u32 slots directly); VU1.macflag/statusflag and
			// VU1.micro_*flags are only updated when the recompiler is exited, so
			// they go stale. Log the live instances instead.
			uint32_t flags[12];
			for (int i = 0; i < 4; i++)
			{
				flags[i] = microVU1.macFlag[i];
				flags[4 + i] = microVU1.clipFlag[i];
				flags[8 + i] = microVU1.statFlag[i];
			}
			vifcap::Flags(flags, sizeof(flags));
		}
		vifcap::VF(VU1.VF, sizeof(VU1.VF));
		u32 vi16[16];
		for (int i = 0; i < 16; i++) vi16[i] = VU1.VI[i].UL;
		vifcap::VI(vi16, sizeof(vi16));
		u32 h = 2166136261u;
		for (int i = 0; i < 0x4000; i++) { h ^= VU1.Mem[i]; h *= 16777619u; }
		vifcap::MemHash(h);
	}
}

#include "common/AlignedMalloc.h"
#include "common/Perf.h"
#include "common/StringUtil.h"

//------------------------------------------------------------------
// Micro VU - Main Functions
//------------------------------------------------------------------

// Only run this once per VU! ;)
void mVUinit(microVU& mVU, uint vuIndex)
{
	std::memset(&mVU.prog, 0, sizeof(mVU.prog));

	mVU.index        =  vuIndex;
	mVU.cop2         =  0;
	mVU.vuMemSize    = (mVU.index ? 0x4000 : 0x1000);
	mVU.microMemSize = (mVU.index ? 0x4000 : 0x1000);
	mVU.progSize     = (mVU.index ? 0x4000 : 0x1000) / 4;
	mVU.progMemMask  =  mVU.progSize-1;
	mVU.cache        = vuIndex ? SysMemory::GetVU1Rec() : SysMemory::GetVU0Rec();
	mVU.prog.x86end  = (vuIndex ? SysMemory::GetVU1RecEnd() : SysMemory::GetVU0RecEnd()) - (mVUcacheSafeZone * _1mb);

	mVU.regAlloc.reset(new microRegAlloc(mVU.index));
}

// Resets Rec Data
void mVUreset(microVU& mVU, bool resetReserve)
{
	if (THREAD_VU1)
	{
		DevCon.Warning("mVU Reset");
		// If MTVU is toggled on during gameplay we need to flush the running VU1 program, else it gets in a mess
		if (VU0.VI[REG_VPU_STAT].UL & 0x100)
		{
			CpuVU1->Execute(vu1RunCycles);
		}
		VU0.VI[REG_VPU_STAT].UL &= ~0x100;
	}

	xSetTextPtr(mVU.textPtr());
	xSetPtr(mVU.cache);
	mVUdispatcherAB(mVU);
	mVUdispatcherCD(mVU);
	mVUGenerateWaitMTVU(mVU);
	mVUGenerateCopyPipelineState(mVU);
	mVUGenerateCompareState(mVU);

	mVU.regs().nextBlockCycles = 0;
	memset(&mVU.prog.lpState, 0, sizeof(mVU.prog.lpState));
	mVU.profiler.Reset(mVU.index);

	// Program Variables
	mVU.prog.cleared  =  1;
	mVU.prog.isSame   = -1;
	mVU.prog.cur      = NULL;
	mVU.prog.total    =  0;
	mVU.prog.curFrame =  0;

	// Setup Dynarec Cache Limits for Each Program
	mVU.prog.x86start = xGetAlignedCallTarget();
	mVU.prog.x86ptr   = mVU.prog.x86start;

	for (u32 i = 0; i < (mVU.progSize / 2); i++)
	{
		if (!mVU.prog.prog[i])
		{
			mVU.prog.prog[i] = new std::deque<microProgram*>();
			continue;
		}
		for (auto it = mVU.prog.prog[i]->begin(); it != mVU.prog.prog[i]->end(); ++it)
		{
			mVUdeleteProg(mVU, it[0]);
		}
		mVU.prog.prog[i]->clear();
		mVU.prog.quick[i].block = NULL;
		mVU.prog.quick[i].prog = NULL;
	}
}

// Free Allocated Resources
void mVUclose(microVU& mVU)
{
	// Delete Programs and Block Managers
	for (u32 i = 0; i < (mVU.progSize / 2); i++)
	{
		if (!mVU.prog.prog[i])
			continue;
		for (auto it = mVU.prog.prog[i]->begin(); it != mVU.prog.prog[i]->end(); ++it)
		{
			mVUdeleteProg(mVU, it[0]);
		}
		safe_delete(mVU.prog.prog[i]);
	}
}

// Clears Block Data in specified range
__fi void mVUclear(mV, u32 addr, u32 size)
{
	if (!mVU.prog.cleared)
	{
		mVU.prog.cleared = 1; // Next execution searches/creates a new microprogram
		std::memset(&mVU.prog.lpState, 0, sizeof(mVU.prog.lpState)); // Clear pipeline state
		for (u32 i = 0; i < (mVU.progSize / 2); i++)
		{
			mVU.prog.quick[i].block = NULL; // Clear current quick-reference block
			mVU.prog.quick[i].prog = NULL; // Clear current quick-reference prog
		}
	}
}

//------------------------------------------------------------------
// Micro VU - Private Functions
//------------------------------------------------------------------

// Deletes a program
__ri void mVUdeleteProg(microVU& mVU, microProgram*& prog)
{
	for (u32 i = 0; i < (mVU.progSize / 2); i++)
	{
		safe_delete(prog->block[i]);
	}
	safe_delete(prog->ranges);
	safe_aligned_free(prog);
}

// Creates a new Micro Program
__ri microProgram* mVUcreateProg(microVU& mVU, int startPC)
{
	microProgram* prog = (microProgram*)_aligned_malloc(sizeof(microProgram), 64);
	memset(prog, 0, sizeof(microProgram));
	prog->idx = mVU.prog.total++;
	prog->ranges = new std::deque<microRange>();
	prog->startPC = startPC;
	if(doWholeProgCompare)
		mVUcacheProg(mVU, *prog); // Cache Micro Program
	double cacheSize = (double)((uptr)mVU.prog.x86end - (uptr)mVU.prog.x86start);
	double cacheUsed = ((double)((uptr)mVU.prog.x86ptr - (uptr)mVU.prog.x86start)) / (double)_1mb;
	double cachePerc = ((double)((uptr)mVU.prog.x86ptr - (uptr)mVU.prog.x86start)) / cacheSize * 100;
	ConsoleColors c = mVU.index ? Color_Orange : Color_Magenta;
	DevCon.WriteLn(c, "microVU%d: Cached Prog = [%03d] [PC=%04x] [List=%02d] (Cache=%3.3f%%) [%3.1fmb]",
		mVU.index, prog->idx, startPC * 8, mVU.prog.prog[startPC]->size() + 1, cachePerc, cacheUsed);
	return prog;
}

// Caches Micro Program
__ri void mVUcacheProg(microVU& mVU, microProgram& prog)
{
	if (!doWholeProgCompare)
	{
		auto cmpOffset = [&](void* x) { return (u8*)x + mVUrange.start; };
		memcpy(cmpOffset(prog.data), cmpOffset(mVU.regs().Micro), (mVUrange.end - mVUrange.start));
	}
	else
	{
		if (!mVU.index)
			memcpy(prog.data, mVU.regs().Micro, 0x1000);
		else
			memcpy(prog.data, mVU.regs().Micro, 0x4000);
	}
	mVUdumpProg(mVU, prog);
}

// Generate Hash for partial program based on compiled ranges...
u64 mVUrangesHash(microVU& mVU, microProgram& prog)
{
	union
	{
		u64 v64;
		u32 v32[2];
	} hash = {0};

	std::deque<microRange>::const_iterator it(prog.ranges->begin());
	for (; it != prog.ranges->end(); ++it)
	{
		if ((it[0].start < 0) || (it[0].end < 0))
		{
			DevCon.Error("microVU%d: Negative Range![%d][%d]", mVU.index, it[0].start, it[0].end);
		}
		for (int i = it[0].start / 4; i < it[0].end / 4; i++)
		{
			hash.v32[0] -= prog.data[i];
			hash.v32[1] ^= prog.data[i];
		}
	}
	return hash.v64;
}

// Prints the ratio of unique programs to total programs
void mVUprintUniqueRatio(microVU& mVU)
{
	std::vector<u64> v;
	for (u32 pc = 0; pc < mProgSize / 2; pc++)
	{
		microProgramList* list = mVU.prog.prog[pc];
		if (!list)
			continue;
		for (auto it = list->begin(); it != list->end(); ++it)
		{
			v.push_back(mVUrangesHash(mVU, *it[0]));
		}
	}
	u32 total = v.size();
	sortVector(v);
	makeUnique(v);
	if (!total)
		return;
	DevCon.WriteLn("%d / %d [%3.1f%%]", v.size(), total, 100. - (double)v.size() / (double)total * 100.);
}

// Compare Cached microProgram to mVU.regs().Micro
__fi bool mVUcmpProg(microVU& mVU, microProgram& prog)
{
	if (doWholeProgCompare)
	{
		if (memcmp((u8*)prog.data, mVU.regs().Micro, mVU.microMemSize))
			return false;
	}
	else
	{
		for (const auto& range : *prog.ranges)
		{
#if defined(PCSX2_DEVBUILD) || defined(_DEBUG)
			if ((range.start < 0) || (range.end < 0))
				DevCon.Error("microVU%d: Negative Range![%d][%d]", mVU.index, range.start, range.end);
#endif
			auto cmpOffset = [&](void* x) { return (u8*)x + range.start; };

			if (memcmp(cmpOffset(prog.data), cmpOffset(mVU.regs().Micro), (range.end - range.start)))
				return false;
		}
	}
	mVU.prog.cleared = 0;
	mVU.prog.cur = &prog;
	mVU.prog.isSame = doWholeProgCompare ? 1 : -1;
	return true;
}

// Searches for Cached Micro Program and sets prog.cur to it (returns entry-point to program)
_mVUt __fi void* mVUsearchProg(u32 startPC, uptr pState)
{
	microVU& mVU = mVUx;
	microProgramQuick& quick = mVU.prog.quick[mVU.regs().start_pc / 8];
	microProgramList*  list  = mVU.prog.prog [mVU.regs().start_pc / 8];

	if (!quick.prog) // If null, we need to search for new program
	{
		for (auto it = list->begin(); it != list->end(); ++it)
		{
			bool b = mVUcmpProg(mVU, *it[0]);

			if (b)
			{
				quick.block = it[0]->block[startPC / 8];
				quick.prog  = it[0];
				list->erase(it);
				list->push_front(quick.prog);

				// Sanity check, in case for some reason the program compilation aborted half way through (JALR for example)
				if (quick.block == nullptr)
				{
					void* entryPoint = mVUblockFetch(mVU, startPC, pState);
					return entryPoint;
				}
				return mVUentryGet(mVU, quick.block, startPC, pState);
			}
		}

		// If cleared and program not found, make a new program instance
		mVU.prog.cleared = 0;
		mVU.prog.isSame  = 1;
		mVU.prog.cur     = mVUcreateProg(mVU, mVU.regs().start_pc/8);
		void* entryPoint = mVUblockFetch(mVU,  startPC, pState);
		quick.block      = mVU.prog.cur->block[startPC/8];
		quick.prog       = mVU.prog.cur;
		list->push_front(mVU.prog.cur);
		//mVUprintUniqueRatio(mVU);
		return entryPoint;
	}

	// If list.quick, then we've already found and recompiled the program ;)
	mVU.prog.isSame = -1;
	mVU.prog.cur = quick.prog;
	// Because the VU's can now run in sections and not whole programs at once
	// we need to set the current block so it gets the right program back
	quick.block = mVU.prog.cur->block[startPC / 8];

	// Sanity check, in case for some reason the program compilation aborted half way through
	if (quick.block == nullptr)
	{
		void* entryPoint = mVUblockFetch(mVU, startPC, pState);
		return entryPoint;
	}
	return mVUentryGet(mVU, quick.block, startPC, pState);
}

//------------------------------------------------------------------
// recMicroVU0 / recMicroVU1
//------------------------------------------------------------------

recMicroVU0 CpuMicroVU0;
recMicroVU1 CpuMicroVU1;

recMicroVU0::recMicroVU0() { m_Idx = 0; IsInterpreter = false; }
recMicroVU1::recMicroVU1() { m_Idx = 1; IsInterpreter = false; }

void recMicroVU0::Reserve()
{
	mVUinit(microVU0, 0);
}
void recMicroVU1::Reserve()
{
	mVUinit(microVU1, 1);
	vu1Thread.Open();
}

void recMicroVU0::Shutdown()
{
	mVUclose(microVU0);
}
void recMicroVU1::Shutdown()
{
	if (vu1Thread.IsOpen())
		vu1Thread.WaitVU();
	mVUclose(microVU1);
}

void recMicroVU0::Reset()
{
	mVUreset(microVU0, true);
}

void recMicroVU0::Step()
{
}

void recMicroVU1::Reset()
{
	vu1Thread.WaitVU();
	vu1Thread.Get_MTVUChanges();
	mVUreset(microVU1, true);
}

void recMicroVU0::SetStartPC(u32 startPC)
{
	VU0.start_pc = startPC;
}

void recMicroVU0::Execute(u32 cycles)
{
	VU0.flags &= ~VUFLAG_MFLAGSET;

	if (!(VU0.VI[REG_VPU_STAT].UL & 1))
		return;
	VU0.VI[REG_TPC].UL <<= 3;

	((mVUrecCall)microVU0.startFunct)(VU0.VI[REG_TPC].UL, cycles);
	VU0.VI[REG_TPC].UL >>= 3;
	if (microVU0.regs().flags & 0x4)
	{
		microVU0.regs().flags &= ~0x4;
		hwIntcIrq(6);
	}
}

void recMicroVU1::SetStartPC(u32 startPC)
{
	VU1.start_pc = startPC;
}

void recMicroVU1::Step()
{
}

void recMicroVU1::Execute(u32 cycles)
{
	if (!THREAD_VU1)
	{
		if (!(VU0.VI[REG_VPU_STAT].UL & 0x100))
			return;
	}
	VU1.VI[REG_TPC].UL <<= 3;
	((mVUrecCall)microVU1.startFunct)(VU1.VI[REG_TPC].UL, cycles);
	VU1.VI[REG_TPC].UL >>= 3;
	if (microVU1.regs().flags & 0x4 && !THREAD_VU1)
	{
		microVU1.regs().flags &= ~0x4;
		hwIntcIrq(7);
	}
}

void recMicroVU0::Clear(u32 addr, u32 size)
{
	mVUclear(microVU0, addr, size);
}
void recMicroVU1::Clear(u32 addr, u32 size)
{
	mVUclear(microVU1, addr, size);
}

void recMicroVU1::ResumeXGkick()
{
	if (!(VU0.VI[REG_VPU_STAT].UL & 0x100))
		return;
	((mVUrecCallXG)microVU1.startFunctXG)();
}

bool SaveStateBase::vuJITFreeze()
{
	if (IsSaving())
		vu1Thread.WaitVU();

	Freeze(microVU0.prog.lpState);
	Freeze(microVU1.prog.lpState);
	return IsOkay();
}

#if 0

#include <zlib.h>

void DumpVUState(u32 n, u32 pc)
{
	const VURegs& r = vuRegs[n];
	const microVU& mVU = (n == 0) ? microVU0 : microVU1;
	static FILE* fp = nullptr;
	static bool fp_opened = false;
	static u32 counter = 0;

	u32 first = pc >> 31;
	pc &= 0x7FFFFFFFu;
	if (first)
		counter++;

#if 0
	if (counter == 184639 && pc == 0x0D70)
		__debugbreak();
#endif

	if (counter < 0)
		return;

	if (!fp_opened)
	{
		fp = std::fopen("C:\\Dumps\\comp\\vulog.txt", "wb");
		fp_opened = true;
	}
	if (fp)
	{
		const microVU& m = (n == 0) ? microVU0 : microVU1;
		fprintf(fp, "%08d VU%u SPC:%04X xPC:%04X BRANCH:%04X VIBACKUP:%04X", counter, n, r.start_pc, pc, mVU.branch, mVU.VIbackup);
#if 1
		//fprintf(fp, " MEM:%08X", crc32(0, (Bytef*)r.Mem, (n == 0) ? VU0_MEMSIZE : VU1_MEMSIZE));
		fprintf(fp, " MAC %08X %08X %08X %08X [%08X %08X %08X %08X]", r.micro_macflags[3], r.micro_macflags[2], r.micro_macflags[1], r.micro_macflags[0], m.macFlag[3], m.macFlag[2], m.macFlag[1], m.macFlag[0]);
		fprintf(fp, " CLIP %08X %08X %08X %08X [%08X %08X %08X %08X]", r.micro_clipflags[3], r.micro_clipflags[2], r.micro_clipflags[1], r.micro_clipflags[0], m.clipFlag[3], m.clipFlag[2], m.clipFlag[1], m.clipFlag[0]);
		fprintf(fp, " STATUS %08X %08X %08X %08X [%08X %08X %08X %08X]", r.micro_statusflags[3], r.micro_statusflags[2], r.micro_statusflags[1], r.micro_statusflags[0], m.statFlag[3], m.statFlag[2], m.statFlag[1], m.statFlag[0]);

		for (u32 i = 0; i < 32; i++)
		{
			const VECTOR& v = r.VF[i];
			fprintf(fp, " VF%u: %08X%08X%08X%08X (%f,%f,%f,%f)", i, v.UL[3], v.UL[2], v.UL[1], v.UL[0], v.F[3], v.F[2], v.F[1], v.F[0]);
		}

		for (u32 i = 0; i < 32; i++)
		{
			const REG_VI& v = r.VI[i];
			fprintf(fp, " VI%u: %08X", i, v.UL);
		}

		fprintf(fp, " ACC: %08X%08X%08X%08X (%f,%f,%f,%f)", r.ACC.UL[3], r.ACC.UL[2], r.ACC.UL[1], r.ACC.UL[0],
			r.ACC.F[3], r.ACC.F[2], r.ACC.F[1], r.ACC.F[0]);
		fprintf(fp, " Q: %08X (%f)", r.q.UL, r.q.F);
		fprintf(fp, " P: %08X (%f)\n", r.p.UL, r.p.F);
#else
		fprintf(fp, " REG:%08X\n", crc32(0, (Bytef*)&r, offsetof(VURegs, idx)));
#endif
		//fflush(fp);
	}
}

#endif
