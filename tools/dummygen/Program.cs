using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

namespace DummyGen;

public sealed class FieldRec
{
    public string Name = "";
    public string Type = "obj";
    public uint Flags;
    public uint Token;
    public long? Offset;
}

public sealed class ParamRec
{
    public string Name = "";
    public string Type = "obj";
}

public sealed class MethodRec
{
    public string Name = "";
    public string Ret = "v";
    public uint Flags;
    public uint Rva;
    public uint Token;
    public int? Slot;
    public long? FileOffset;
    public List<ParamRec> Params = new();
}

public sealed class TypeRec
{
    public int Id;
    public string Ns = "";
    public string Name = "";
    public string Kind = "class";
    public int Parent = -1;
    public uint Flags;
    public List<FieldRec> Fields = new();
    public List<MethodRec> Methods = new();
    public List<int> Ifaces = new();
}

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: dummygen <input.jsonl> <output.dll> [--verify-only]");
            return 2;
        }
        string input = args[0];
        string output = args[1];
        var types = Load(input);
        Console.WriteLine($"loaded {types.Count} types, {types.Sum(t => t.Fields.Count)} fields, {types.Sum(t => t.Methods.Count)} methods");
        Emit(types, output);
        Verify(output, types);
        return 0;
    }

    static List<TypeRec> Load(string path)
    {
        var types = new List<TypeRec>();
        TypeRec? cur = null;
        using var reader = new StreamReader(path);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            using var doc = JsonDocument.Parse(line);
            var r = doc.RootElement;
            string k = r.GetProperty("k").GetString() ?? "";
            switch (k)
            {
                case "T":
                    cur = new TypeRec
                    {
                        Id = r.GetProperty("id").GetInt32(),
                        Ns = r.GetProperty("ns").GetString() ?? "",
                        Name = r.GetProperty("name").GetString() ?? "",
                        Kind = r.GetProperty("kind").GetString() ?? "class",
                        Parent = r.GetProperty("parent").GetInt32(),
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    types.Add(cur);
                    break;
                case "F":
                    var fr = new FieldRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Type = r.GetProperty("type").GetString() ?? "obj",
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    if (r.TryGetProperty("token", out var ftok)) fr.Token = ftok.GetUInt32();
                    if (r.TryGetProperty("off", out var foff) && foff.ValueKind == JsonValueKind.Number)
                        fr.Offset = foff.GetInt64();
                    cur!.Fields.Add(fr);
                    break;
                case "M":
                    var m = new MethodRec
                    {
                        Name = r.GetProperty("name").GetString() ?? "",
                        Ret = r.GetProperty("ret").GetString() ?? "v",
                        Flags = r.GetProperty("flags").GetUInt32(),
                    };
                    if (r.TryGetProperty("rva", out var mrva)) m.Rva = mrva.GetUInt32();
                    if (r.TryGetProperty("token", out var mtok)) m.Token = mtok.GetUInt32();
                    if (r.TryGetProperty("slot", out var mslot) && mslot.ValueKind == JsonValueKind.Number)
                        m.Slot = mslot.GetInt32();
                    if (r.TryGetProperty("foff", out var mfoff) && mfoff.ValueKind == JsonValueKind.Number)
                        m.FileOffset = mfoff.GetInt64();
                    foreach (var p in r.GetProperty("params").EnumerateArray())
                        m.Params.Add(new ParamRec
                        {
                            Name = p.GetProperty("n").GetString() ?? "",
                            Type = p.GetProperty("t").GetString() ?? "obj",
                        });
                    cur!.Methods.Add(m);
                    break;
                case "I":
                    cur!.Ifaces.Add(r.GetProperty("iface").GetInt32());
                    break;
            }
        }
        return types;
    }

    static void Emit(List<TypeRec> types, string output)
    {
        var mb = new MetadataBuilder();
        // module + assembly
        var mvid = mb.GetOrAddGuid(Guid.NewGuid());
        mb.AddModule(0, mb.GetOrAddString("DummyDll.dll"), mvid, default, default);
        mb.AddAssembly(mb.GetOrAddString("DummyDll"), new Version(0, 0, 0, 0),
            default, default, (AssemblyFlags)0, AssemblyHashAlgorithm.None);

        // special type handles (all defined in this same module, like the IL2CPP metadata image set)
        int FindType(string ns, string name)
        {
            for (int i = 0; i < types.Count; i++)
                if (types[i].Ns == ns && types[i].Name == name) return i;
            return -1;
        }
        int objId = FindType("System", "Object");
        int vtId = FindType("System", "ValueType");
        int enumId = FindType("System", "Enum");
        if (objId < 0) throw new Exception("System.Object missing");
        var objHandle = MetadataTokens.TypeDefinitionHandle(objId + 1);
        var vtHandle = vtId >= 0 ? MetadataTokens.TypeDefinitionHandle(vtId + 1) : default;
        var enumHandle = enumId >= 0 ? MetadataTokens.TypeDefinitionHandle(enumId + 1) : default;

        // precompute row counts per type
        int fieldRows = 1, methodRows = 1, paramRows = 1;
        var fieldStart = new int[types.Count + 1];
        var methodStart = new int[types.Count + 1];
        for (int i = 0; i < types.Count; i++)
        {
            fieldStart[i] = fieldRows;
            methodStart[i] = methodRows;
            fieldRows += types[i].Fields.Count;
            methodRows += types[i].Methods.Count;
            foreach (var m in types[i].Methods) paramRows += m.Params.Count;
        }
        fieldStart[types.Count] = fieldRows;
        methodStart[types.Count] = methodRows;

        // ---- TypeDef rows (in metadata order, so handle = id + 1) ----
        for (int i = 0; i < types.Count; i++)
        {
            var t = types[i];
            var ta = TypeAttributes.NotPublic;
            uint vis = (uint)(t.Flags & 0x7);
            if (vis == 1) ta = TypeAttributes.Public;
            EntityHandle baseType = default;
            if (i == 0)
            {
                ta = 0; // <Module>
            }
            else if (t.Kind == "interface")
            {
                ta |= TypeAttributes.Interface | TypeAttributes.Abstract;
            }
            else if (t.Kind == "struct")
            {
                ta |= TypeAttributes.Sealed;
                baseType = vtHandle;
            }
            else if (t.Kind == "enum")
            {
                ta |= TypeAttributes.Sealed;
                baseType = enumHandle;
            }
            else
            {
                if ((t.Flags & 0x80) != 0) ta |= TypeAttributes.Abstract;
                if ((t.Flags & 0x100) != 0) ta |= TypeAttributes.Sealed;
                baseType = t.Parent >= 0 && t.Parent < types.Count
                    ? MetadataTokens.TypeDefinitionHandle(t.Parent + 1)
                    : objHandle;
            }
            mb.AddTypeDefinition(ta,
                mb.GetOrAddString(t.Ns),
                mb.GetOrAddString(t.Name),
                baseType,
                MetadataTokens.FieldDefinitionHandle(fieldStart[i]),
                MetadataTokens.MethodDefinitionHandle(methodStart[i]));
        }

        // ---- GenericParam rows (arity from the metadata type name suffix) ----
        int genericParamRows = 0;
        foreach (var t in types)
        {
            int arity = ArityOf(t.Name);
            if (arity == 0) continue;
            var ownerTd = MetadataTokens.TypeDefinitionHandle(t.Id + 1);
            for (int k = 0; k < arity; k++)
            {
                mb.AddGenericParameter(ownerTd, GenericParameterAttributes.None,
                    mb.GetOrAddString("T" + (k + 1)), k);
                genericParamRows++;
            }
        }

        // ---- InterfaceImpl rows ----
        foreach (var t in types)
        {
            var owner = MetadataTokens.TypeDefinitionHandle(t.Id + 1);
            foreach (int f in t.Ifaces)
            {
                if (f < 0 || f >= types.Count) continue;
                mb.AddInterfaceImplementation(owner, MetadataTokens.TypeDefinitionHandle(f + 1));
            }
        }

        // ---- FieldDef rows ----
        foreach (var t in types)
        {
            foreach (var f in t.Fields)
            {
                var fa = (FieldAttributes)(f.Flags & 0x7)
                         | FieldAttributes.Static & ((FieldAttributes)f.Flags & FieldAttributes.Static);
                // map the reference tool behaviour: constants become plain static fields (we do not
                // emit Constant/Marshal tables in v1), so clear Literal/HasDefault/HasFieldMarshal.
                fa = (FieldAttributes)((uint)fa & ~0x40u & ~0x8000u & ~0x1000u);
                if ((f.Flags & 0x10) != 0) fa |= FieldAttributes.Static;
                if ((f.Flags & 0x20) != 0) fa |= FieldAttributes.InitOnly;
                var blob = new BlobBuilder();
                var fenc = new BlobEncoder(blob).FieldSignature();
                WriteSigType(fenc, f.Type, types);
                mb.AddFieldDefinition(fa, mb.GetOrAddString(f.Name), mb.GetOrAddBlob(blob));
            }
        }

        // ---- MethodDef rows + params ----
        var ilBuilder = new BlobBuilder();
        var bodyStream = new MethodBodyStreamEncoder(ilBuilder);
        foreach (var t in types)
        {
            bool isIface = t.Kind == "interface";
            foreach (var me in t.Methods)
            {
                var ma = (MethodAttributes)(me.Flags & 0xFFFFu);
                ma &= ~MethodAttributes.PinvokeImpl;
                ma &= ~MethodAttributes.UnmanagedExport;
                MethodImplAttributes impl = MethodImplAttributes.IL;
                bool isStatic = (me.Flags & 0x10) != 0;
                if (isIface)
                {
                    ma = MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Abstract
                         | MethodAttributes.HideBySig | MethodAttributes.NewSlot;
                    if (isStatic) ma |= MethodAttributes.Static;
                }
                bool isAbstract = (ma & MethodAttributes.Abstract) != 0 || isIface;
                if (isAbstract && !isIface)
                {
                    ma |= MethodAttributes.Abstract;
                }
                BlobBuilder? sigBlob = null;
                {
                    var bb = new BlobBuilder();
                    var sig = new BlobEncoder(bb).MethodSignature(isInstanceMethod: !isStatic);
                    sig.Parameters(me.Params.Count, out var retEnc, out var parsEnc);
                    if (me.Ret == "v") retEnc.Void();
                    else
                    {
                        var re = retEnc.Type(me.Ret.StartsWith("&"));
                        WriteSigType(re, me.Ret.TrimStart('&'), types);
                    }
                    foreach (var p in me.Params)
                    {
                        var pe = parsEnc.AddParameter();
                        var enc = pe.Type(p.Type.StartsWith("&"));
                        WriteSigType(enc, p.Type.TrimStart('&'), types);
                    }
                    sigBlob = bb;
                }
                int bodyOffset = -1;
                if (!isAbstract)
                {
                    var enc = new InstructionEncoder(new BlobBuilder());
                    if (me.Ret == "v")
                    {
                        enc.OpCode(ILOpCode.Ret);
                    }
                    else
                    {
                        enc.OpCode(ILOpCode.Ldnull);
                        enc.OpCode(ILOpCode.Throw);
                    }
                    bodyOffset = bodyStream.AddMethodBody(enc, maxStack: 1);
                }
                mb.AddMethodDefinition(ma, impl, mb.GetOrAddString(me.Name),
                    mb.GetOrAddBlob(sigBlob!), bodyOffset,
                    MetadataTokens.ParameterHandle(paramRows));
                foreach (var p in me.Params)
                {
                    mb.AddParameter(0, mb.GetOrAddString(p.Name), paramRows == 0 ? 1 : 1);
                    paramRows++;
                }
            }
        }

        // ---- Il2CppDummyDll-style custom attributes (Address / FieldOffset) ----
        int attrBaseId = FindType("System", "Attribute");
        EntityHandle attrBaseHandle = attrBaseId >= 0
            ? MetadataTokens.TypeDefinitionHandle(attrBaseId + 1) : objHandle;
        var attrCtors = new List<MethodDefinitionHandle>();
        var attrFieldNames = new[] { new[] { "RVA", "Offset", "VA", "Slot" }, new[] { "Offset" } };
        var attrTypeNames = new[] { "AddressAttribute", "FieldOffsetAttribute" };
        for (int ai = 0; ai < attrTypeNames.Length; ai++)
        {
            int firstField = fieldRows;
            int firstMethod = methodRows;
            mb.AddTypeDefinition(TypeAttributes.Public | TypeAttributes.Sealed,
                mb.GetOrAddString("Il2CppDummyDll"), mb.GetOrAddString(attrTypeNames[ai]), attrBaseHandle,
                MetadataTokens.FieldDefinitionHandle(firstField),
                MetadataTokens.MethodDefinitionHandle(firstMethod));
            foreach (var fn in attrFieldNames[ai])
            {
                var fbb = new BlobBuilder();
                new BlobEncoder(fbb).FieldSignature().String();
                mb.AddFieldDefinition(FieldAttributes.Public, mb.GetOrAddString(fn), mb.GetOrAddBlob(fbb));
                fieldRows++;
            }
            var sbb = new BlobBuilder();
            new BlobEncoder(sbb).MethodSignature(isInstanceMethod: true).Parameters(0, out var retEb, out _);
            retEb.Void();
            var bodyEnc = new InstructionEncoder(new BlobBuilder());
            bodyEnc.OpCode(ILOpCode.Ret);
            var ctor = mb.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                MethodImplAttributes.IL, mb.GetOrAddString(".ctor"), mb.GetOrAddBlob(sbb),
                bodyStream.AddMethodBody(bodyEnc, maxStack: 0), MetadataTokens.ParameterHandle(paramRows));
            methodRows++;
            attrCtors.Add(ctor);
        }
        var addressCtor = attrCtors[0];
        var fieldOffsetCtor = attrCtors[1];
        static void WriteSerString(BlobBuilder bb, string value)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            if (bytes.Length < 0x80)
            {
                bb.WriteByte((byte)bytes.Length);
            }
            else
            {
                int len = bytes.Length;
                bb.WriteByte((byte)(0x80 | (len & 0x3F)));
                bb.WriteByte((byte)(len >> 6));
            }
            bb.WriteBytes(bytes);
        }
        BlobHandle NamedArgsBlob((string Name, string Value)[] args)
        {
            var bb = new BlobBuilder();
            bb.WriteUInt16(0x0001);
            bb.WriteUInt16((ushort)args.Length);
            foreach (var (name, value) in args)
            {
                bb.WriteByte(0x53); // named argument: field
                bb.WriteByte(0x0E); // field type: string
                WriteSerString(bb, name);
                WriteSerString(bb, value);
            }
            return mb.GetOrAddBlob(bb);
        }
        foreach (var t in types)
        {
            foreach (var f in t.Fields)
            {
                if (f.Token == 0 || f.Offset is null) continue;
                var fh = MetadataTokens.FieldDefinitionHandle((int)(f.Token - 0x04000000));
                mb.AddCustomAttribute(fh, fieldOffsetCtor,
                    NamedArgsBlob(new[] { ("Offset", "0x" + f.Offset.Value.ToString("X")) }));
            }
            foreach (var me in t.Methods)
            {
                if (me.Token == 0 || me.Rva == 0) continue;
                var mh = MetadataTokens.MethodDefinitionHandle((int)(me.Token - 0x06000000));
                var args = new List<(string, string)>
                {
                    ("RVA", "0x" + me.Rva.ToString("X")),
                };
                if (me.FileOffset is long fo) args.Add(("Offset", "0x" + fo.ToString("X")));
                args.Add(("VA", "0x" + (0x140000000UL + me.Rva).ToString("X")));
                if (me.Slot is int sl && sl >= 0) args.Add(("Slot", sl.ToString()));
                mb.AddCustomAttribute(mh, addressCtor, NamedArgsBlob(args.ToArray()));
            }
        }
        // ---- PE image ----
        var peHeader = new PEHeaderBuilder(
            machine: Machine.I386,
            imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll);
        var peBuilder = new ManagedPEBuilder(peHeader, new MetadataRootBuilder(mb), ilBuilder);
        var blobOut = new BlobBuilder();
        peBuilder.Serialize(blobOut);
        File.WriteAllBytes(output, blobOut.ToArray());
        Console.WriteLine($"wrote {output} ({new FileInfo(output).Length / 1024} KB)");
    }

    static int ArityOf(string name)
    {
        int dot = name.LastIndexOf('.');
        string seg = dot >= 0 ? name.Substring(dot + 1) : name;
        int bt = seg.LastIndexOf('`');
        if (bt < 0) return 0;
        if (int.TryParse(seg.Substring(bt + 1), out int n) && n > 0 && n < 64) return n;
        return 0;
    }

    static void WriteSigType(SignatureTypeEncoder enc, string s, List<TypeRec> types)
    {
        if (s.StartsWith("p")) { WriteSigType(enc.Pointer(), s.Substring(1), types); return; }
        if (s.StartsWith("a")) { WriteSigType(enc.SZArray(), s.Substring(1), types); return; }
        switch (s)
        {
            case "v": enc.VoidPointer(); return;
            case "b": enc.Boolean(); return;
            case "c": enc.Char(); return;
            case "s8": enc.SByte(); return;
            case "u8": enc.Byte(); return;
            case "s16": enc.Int16(); return;
            case "u16": enc.UInt16(); return;
            case "s32": enc.Int32(); return;
            case "u32": enc.UInt32(); return;
            case "s64": enc.Int64(); return;
            case "u64": enc.UInt64(); return;
            case "f4": enc.Single(); return;
            case "f8": enc.Double(); return;
            case "str": enc.String(); return;
            case "ip": enc.IntPtr(); return;
            case "up": enc.UIntPtr(); return;
            case "obj": enc.Type(MetadataTokens.TypeDefinitionHandle(
                types.FindIndex(t => t.Ns == "System" && t.Name == "Object") + 1), false); return;
            case "tr": enc.TypedReference(); return;
        }
        if (s.StartsWith("t"))
        {
            int id = int.Parse(s.Substring(1));
            bool isValue = id >= 0 && id < types.Count &&
                (types[id].Kind == "struct" || types[id].Kind == "enum");
            enc.Type(MetadataTokens.TypeDefinitionHandle(id + 1), isValue);
            return;
        }
        // fallback: object
        enc.Type(MetadataTokens.TypeDefinitionHandle(types.FindIndex(t => t.Ns == "System" && t.Name == "Object") + 1), false);
    }

    static void Verify(string path, List<TypeRec> expected)
    {
        using var fs = File.OpenRead(path);
        using var pe = new PEReader(fs);
        var md = pe.GetMetadataReader();
        int typeCount = 0, fieldCount = 0, methodCount = 0, paramCount = 0, ifaceCount = 0, bodyCount = 0;
        foreach (var th in md.TypeDefinitions)
        {
            typeCount++;
            var td = md.GetTypeDefinition(th);
            foreach (var fh in td.GetFields()) { fieldCount++; }
            foreach (var mh in td.GetMethods())
            {
                methodCount++;
                var mdef = md.GetMethodDefinition(mh);
                if (mdef.RelativeVirtualAddress != 0) bodyCount++;
                foreach (var ph in mdef.GetParameters()) paramCount++;
            }
            foreach (var ih in td.GetInterfaceImplementations()) ifaceCount++;
        }
        int attrRowCount = md.CustomAttributes.Count;
        int genericParamRows = md.GetTableRowCount(TableIndex.GenericParam);
        int expGenericParams = expected.Sum(t => ArityOf(t.Name));
        Console.WriteLine($"verify: types={typeCount} fields={fieldCount} methods={methodCount} " +
                          $"params={paramCount} ifaces={ifaceCount} bodies={bodyCount} customAttrs={attrRowCount} genericParams={genericParamRows}");
        if (genericParamRows != expGenericParams) throw new Exception($"generic param count mismatch {genericParamRows} vs {expGenericParams}");
        // +2 attribute types (AddressAttribute, FieldOffsetAttribute) with 5 fields and 2 ctors
        if (typeCount != expected.Count + 2) throw new Exception($"type count mismatch {typeCount} vs {expected.Count + 2}");
        int expFields = expected.Sum(t => t.Fields.Count) + 5;
        int expMethods = expected.Sum(t => t.Methods.Count) + 2;
        int expParams = expected.Sum(t => t.Methods.Sum(m => m.Params.Count));
        if (fieldCount != expFields) throw new Exception($"field count mismatch {fieldCount} vs {expFields}");
        if (methodCount != expMethods) throw new Exception($"method count mismatch {methodCount} vs {expMethods}");
        if (paramCount != expParams) throw new Exception($"param count mismatch {paramCount} vs {expParams}");
        if (attrRowCount == 0) throw new Exception("no custom attributes emitted");
        // targeted custom-attribute validation: decode a sample of blobs and resolve their ctor type
        var ctorNames = new System.Collections.Generic.Dictionary<EntityHandle, string>();
        int checkedAttrs = 0; int sampleShown = 0;
        foreach (var ch in md.CustomAttributes)
        {
            var ca = md.GetCustomAttribute(ch);
            if (!ctorNames.TryGetValue(ca.Constructor, out var ctorName))
            {
                var mh2 = (MethodDefinitionHandle)ca.Constructor;
                var mdef2 = md.GetMethodDefinition(mh2);
                var td2 = md.GetTypeDefinition(mdef2.GetDeclaringType());
                ctorName = md.GetString(td2.Name);
                ctorNames[ca.Constructor] = ctorName;
            }
            var blob = md.GetBlobBytes(ca.Value);
            if (blob.Length < 4 || blob[0] != 1 || blob[1] != 0)
                throw new Exception($"custom attribute blob with bad prolog ({blob.Length} bytes, ctor {ctorName})");
            int named = blob[2] | (blob[3] << 8);
            if (named == 0) throw new Exception($"custom attribute {ctorName} has no named arguments");
            if (ctorName != "AddressAttribute" && ctorName != "FieldOffsetAttribute")
                throw new Exception($"unexpected custom attribute type {ctorName}");
            checkedAttrs++;
            if (sampleShown < 3)
            {
                string text = System.Text.Encoding.UTF8.GetString(blob, 0, Math.Min(blob.Length, 60));
                Console.WriteLine($"  attr sample: ctor={ctorName} named={named} bytes={blob.Length} ascii={text}");
                sampleShown++;
            }
            if (checkedAttrs >= 500) break;
        }
        Console.WriteLine($"verify: custom attributes decoded OK (sample {checkedAttrs}, table rows {attrRowCount})");
        Console.WriteLine("verify: OK (counts match the JSONL export; attribute rows present)");
    }
}
