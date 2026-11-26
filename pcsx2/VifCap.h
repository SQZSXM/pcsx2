// VIF1 capture logger for PCSX2 (route A).
// Header-only on purpose: drop it next to the three hook sites and include it.
//
// Record stream (little-endian, x86 native):
//   header : "VIFCAP01"                        (8 bytes)
//   record : u8 type | u8 pad[3] | u32 len | payload[len]
//     type 1 MEM  : u32 addr | bytes        (VU1 data-memory image after a VIF UNPACK)
//     type 2 TOP  : u32 value               (XTOP cursor)
//     type 3 ITOP : u32 value               (XITOP cursor / "data available")
//     type 4 KICK : u32 addr | bytes        (XGKICK packet as sent to GIF)
//     type 5 FRAME: u32 index               (optional marker)
//
// Build notes: disable MTVU and Instant VU1 for a deterministic capture.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace vifcap {

enum : uint8_t { REC_MEM = 1, REC_TOP = 2, REC_ITOP = 3, REC_KICK = 4, REC_FRAME = 5, REC_VUREGS = 6, REC_MVUCALL = 7, REC_BLOCK = 8, REC_INSN = 9, REC_MICRO = 10, REC_VF = 11, REC_VI = 12, REC_MEMHASH = 13, REC_MEMSYNC = 14, REC_FLAGS = 15, REC_XGKICKSTATE = 16, REC_KICKINFO = 17, REC_MEMWATCH = 18, REC_MEMREAD = 19, REC_BLOCKCODE = 20, REC_VFTRACE = 21 };

// Per-instruction VF/ACC/Q sample (emitted code stores one VF register into
// g_vifcap_vfbuf before the hook runs).  Slices 74+ of the analysed game diverge
// only in computed values, which the block-boundary checks cannot see.
// (VfTrace itself is defined below, after Rec().)
extern uint32_t g_vifcap_vfidx;
extern uint32_t g_vifcap_vfbuf[4];

// Set by the emitted LQ/LQI/LQD code with the effective byte offset it is about to
// read; vifcap_log_insn() turns it into a REC_MEMREAD record (the replay compares
// its own effective addresses, which is how a VI divergence is located).
extern uint32_t g_vifcap_ldaddr;

inline FILE*& file()
{
    static FILE* f = nullptr;
    return f;
}

inline bool Enabled() { return file() != nullptr; }

inline void Close()
{
    if (file())
    {
        std::fclose(file());
        file() = nullptr;
    }
}

inline void Open(const char* path)
{
    Close();
    file() = std::fopen(path, "wb");
    if (file())
        std::fwrite("VIFCAP01", 1, 8, file());
}

inline void Rec(uint8_t type, const void* a, uint32_t alen, const void* b, uint32_t blen)
{
    if (!file())
        return;
    std::fwrite(&type, 1, 1, file());
    const uint8_t pad[3] = {0, 0, 0};
    std::fwrite(pad, 1, 3, file());
    const uint32_t len = alen + blen;
    std::fwrite(&len, 4, 1, file());
    if (alen)
        std::fwrite(a, 1, alen, file());
    if (blen)
        std::fwrite(b, 1, blen, file());
}

inline void Mem(uint32_t addr, const void* data, uint32_t len) { Rec(REC_MEM, &addr, 4, data, len); }

// VU1 data-memory resync at a microVU batch entry: same payload as Mem, but the
// replay must NOT treat it as an MSCAL entry (it carries no VUREGS).
inline void MemSync(uint32_t addr, const void* data, uint32_t len) { Rec(REC_MEMSYNC, &addr, 4, data, len); }
inline void Top(uint32_t v) { Rec(REC_TOP, &v, 4, nullptr, 0); }
inline void Itop(uint32_t v) { Rec(REC_ITOP, &v, 4, nullptr, 0); }
inline void Kick(uint32_t addr, const void* data, uint32_t len) { Rec(REC_KICK, &addr, 4, data, len); }

// Context of the next REC_KICK: the VU instruction pc whose emitted code performed
// the transfer (compile-time constant for the one-shot path) plus the VU cycle
// counter at that moment.  Lets the replay compare the packet against the VU
// memory of exactly that point instead of guessing the transfer time.
inline void KickInfo(uint32_t pc, uint32_t cycles)
{
    const uint32_t b[2] = {pc, cycles};
    Rec(REC_KICKINFO, b, sizeof(b), nullptr, 0);
}

// Effective address (and the data at that address) of an LQ/LQI/LQD, recorded by
// the per-instruction hook.  Comparing it with the replay's own effective
// addresses shows exactly where a VI (pointer) state diverges.
// Instruction words of a block as the JIT compiled it.  microVU keeps compiled
// blocks cached across microcode re-uploads, so a block can execute code that no
// longer exists in the current micro memory; the replay must use these words.
inline void BlockCode(uint32_t pc, uint32_t count, const void* words, uint32_t bytes)
{
    const uint32_t hdr[2] = {pc, count};
    Rec(REC_BLOCKCODE, hdr, sizeof(hdr), words, bytes);
}

inline void MemRead(uint32_t pc, uint32_t addr, const uint32_t* data)
{
    uint32_t buf[6];
    buf[0] = pc;
    buf[1] = addr;
    memcpy(buf + 2, data, 16);
    Rec(REC_MEMREAD, buf, sizeof(buf), nullptr, 0);
}

// Per-instruction VF/ACC/Q sample (see the extern declarations above).
inline void VfTrace(uint32_t pc, const uint32_t* vf, const uint32_t* acc, uint32_t q)
{
    uint32_t b[10];
    b[0] = pc;
    memcpy(b + 1, vf, 16);
    memcpy(b + 5, acc, 16);
    b[9] = q;
    Rec(REC_VFTRACE, b, sizeof(b), nullptr, 0);
}

// Per-instruction memory watch: windows of VU1 memory whose 4-byte changes are
// logged together with the pc that caused them (A's block hashes cannot show
// mid-block state).
inline void MemWatch(uint32_t pc, const uint32_t* addr, const uint32_t* value, uint32_t count)
{
    static thread_local uint8_t buf[8 + 8 * 64];
    if (count > 64)
        count = 64;
    memcpy(buf, &pc, 4);
    memcpy(buf + 4, &count, 4);
    for (uint32_t i = 0; i < count; i++)
    {
        memcpy(buf + 8 + i * 8, &addr[i], 4);
        memcpy(buf + 12 + i * 8, &value[i], 4);
    }
    Rec(REC_MEMWATCH, buf, 8 + count * 8, nullptr, 0);
}
inline void Frame(uint32_t n) { Rec(REC_FRAME, &n, 4, nullptr, 0); }
inline void VU1Regs(const void* data, uint32_t len) { Rec(REC_VUREGS, data, len, nullptr, 0); }
inline void VF(const void* data, uint32_t len) { Rec(REC_VF, data, len, nullptr, 0); }

inline void VI(const void* data, uint32_t len) { Rec(REC_VI, data, len, nullptr, 0); }

inline void MemHash(uint32_t h) { Rec(REC_MEMHASH, &h, 4, nullptr, 0); }

// microVU keeps four mac/clip/status flag instances; they live in
// VU1.micro_*flags at block boundaries, so log them as one 48-byte record.
inline void Flags(const void* data, uint32_t len) { Rec(REC_FLAGS, data, len, nullptr, 0); }

inline void Micro(uint32_t addr, const void* data, uint32_t len)
{
    static thread_local uint8_t buf[4 + 0x4000];
    if (len > 0x4000) len = 0x4000;
    memcpy(buf, &addr, 4);
    memcpy(buf + 4, data, len);
    Rec(REC_MICRO, buf, 4 + len, nullptr, 0);
}

inline void Insn(uint32_t pc) { Rec(REC_INSN, &pc, 4, nullptr, 0); }

inline void Block(uint32_t startpc, uint32_t cycles, uint32_t count, uint32_t vi2, uint32_t vi3, uint32_t vi12,
                  uint32_t macflag, uint32_t statusflag)
{
    const uint32_t b[8] = {startpc, cycles, count, vi2, vi3, vi12, macflag, statusflag};
    Rec(REC_BLOCK, b, sizeof(b), nullptr, 0);
}

inline void MVUCall(uint32_t startpc, uint32_t budget, uint32_t used, const uint32_t* vi)
{
    uint32_t b[19];
    b[0] = startpc; b[1] = budget; b[2] = used;
    for (int i = 0; i < 16; i++) b[3 + i] = vi[i];
    Rec(REC_MVUCALL, b, sizeof(b), nullptr, 0);
}

// XGKICK transfer state at capture open.  The emulator is already running when
// the capture starts, so a transfer can be pending across the first record:
//   * `hack` = EmuConfig.Gamefixes.XgKickHack selects between the VU1 delayed
//     state machine (`_vuXGKICKTransfermVU`) and the one-shot path
//     (`mVU_XGKICK_`, driven by a countdown carried in the block pState);
//   * `enable/addr/sizeremaining/cyclecount/diff/endpacket` are the VU1 state
//     machine fields (used when hack != 0);
//   * `pstate_xgkick`/`pstate_cycles` are microVU1.prog.lpState.xgkick(cycles)
//     and `vixgkick` is microVU1.VIxgkick -- the pending one-shot kick.
inline void XgKickState(uint32_t enable, uint32_t addr, uint32_t sizeremaining,
                        uint32_t cyclecount, uint32_t diff, uint32_t endpacket,
                        uint32_t hack, uint32_t lastcycle, uint32_t pstate_xgkick,
                        uint32_t pstate_cycles, uint32_t vixgkick)
{
    const uint32_t b[11] = {enable, addr, sizeremaining, cyclecount, diff,
                            endpacket, hack, lastcycle, pstate_xgkick,
                            pstate_cycles, vixgkick};
    Rec(REC_XGKICKSTATE, b, sizeof(b), nullptr, 0);
}

} // namespace vifcap
