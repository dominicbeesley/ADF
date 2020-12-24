#!/usr/bin/perl

#
# (c) Dominic Beesley 2020
#
# MIT licence, see LICENCE.txt


# A simple ADF imager

use strict;
use File::Basename qw( fileparse dirname );
use File::Path qw( make_path );
use File::Spec;

my	$BADSPECCHARS = "\$%&@:^.";
my	$FLAGNAMES = "RWLDErwepx";


use constant {

	FLAG_R => 0x001,
	FLAG_W => 0x002,
	FLAG_L => 0x004,
	FLAG_D => 0x008,
	FLAG_E => 0x010,
	FLAG_r => 0x020,
	FLAG_w => 0x040,
	FLAG_e => 0x080,
	FLAG_p => 0x100


};

my	$ROOTDIRENT = {
	name => "\$",
	flags => FLAG_D | FLAG_L | FLAG_R,
	load => 0x00000000,
	exec => 0x00000000,
	length => 0x00000500,
	sector => 0x000002,
	seq => 0
};


sub read32bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 4) != 4) {
		return 0;
	}
	else
	{
		$_[1] = unpack("L", $buf);
		return 1;
	}

}


sub read24bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 3) != 3) {
		return 0;
	}
	else
	{
		my @n = unpack("CCC", $buf);
		$_[1] = @n[0] + (@n[1] << 8) + (@n[2] << 16);
		return 1;
	}

}

sub read16bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 2) != 2) {
		return 0;
	}
	else
	{
		my @n = unpack("CC", $buf);
		$_[1] = @n[0] + (@n[1] << 8);
		return 1;
	}

}


sub read8bit($$) {
	my $fh = $_[0];
	my $buf;

	if (read($fh, $buf, 1) != 1) {
		return 0;
	}
	else
	{
		my @n = unpack("C", $buf);
		$_[1] = @n[0];
		return 1;
	}

}


sub readbytes($$$) {
	my $fh = $_[0];
	my $len = $_[1];
	my $buf;

	if (read($fh, $buf, $len) != $len) {
		return 0;
	}
	else
	{
		$_[2] = $buf;
		return 1;
	}

}

sub ckadd($$) {
	my $ret = $_[0];
	if ($ret > 255) {
		$ret = ($ret + 1) & 0xFF;
	}
	$ret += $_[1] & 0xFF;
	$_[0] = $ret;
}

sub ckadd24($$) {

	ckadd($_[0], $_[1] >> 16);
	ckadd($_[0], $_[1] >> 8);
	ckadd($_[0], $_[1]);	
}

sub ckadd16($$) {

	ckadd($_[0], $_[1] >> 8);
	ckadd($_[0], $_[1]);	
}

#speak to JGH about this - not quite right in doco?
sub ckaddstr($$) {

	for my $c (reverse unpack("C*", $_[1])) {
		ckadd($_[0], $c);	
	}

}


sub makesec0cksum($) {
	my ($disk) = @_;

	my $ret = 255;

	ckadd24($ret, $disk->{disksize});
	ckaddstr($ret, $disk->{ronameeven});
	ckadd24($ret, $disk->{l3sec1});

	for (my $i = 81; $i >= 0; $i--) {
		ckadd24($ret, $disk->{fsmap}->{starts}->[$i]);
	}


	return $ret & 0xFF;
}

sub makesec1cksum($) {
	my ($disk) = @_;

	my $ret = 255;

	ckadd($ret, $disk->{fsmap}->{len3});
	ckadd($ret, $disk->{opt4});
	ckadd16($ret, $disk->{diskid});
	ckaddstr($ret, $disk->{ronameodd});


	for (my $i = 81; $i >= 0; $i--) {
		ckadd24($ret, $disk->{fsmap}->{lengths}->[$i]);
	}


	return $ret & 0xFF;
}


sub makecksumraw($) {
	my ($str) = @_;
	my $ret = 255;
	ckaddstr($ret, $str);
	return $ret & 0xFF;
}

sub pack24($) {
	my ($x) = @_;
	return pack "CCC", $x, $x >> 8, $x >> 16;
}

sub format_disk($$) {
	my ($size, $interleave) = @_;

	my %disk = ();

	my $sectorsize = ($size / 256);

	$sectorsize >= 0x07 or die "Too small";

	$disk{fsmap}->{starts} = [ 0x2 ];
	$disk{fsmap}->{lengths} = [ $sectorsize - 0x2 ];
	$disk{fsmap}->{len3} = 0x03;
	$disk{disksize} = $sectorsize;
	$disk{diskid} = 1 + rand(65535);
	$disk{opt4} = 0;
	$disk{data} = "\0" x 256 * ($sectorsize - 0x2);

	createdir_int(\%disk, undef, undef, "\$");

	return \%disk;
}

sub packfsmap($) {
	my ($disk) = @_;

	my $ret0 = "";

	for (my $i = 0; $i < 82; $i++) {
		if ($i > scalar(@{$disk->{fsmap}->{starts}}))
		{
			$ret0 .= pack24(0);
		} else {
			$ret0 .= pack24($disk->{fsmap}->{starts}->[$i]);
		}
	}

	$ret0 .= pack24($disk->{l3sec1});
	$ret0 .= pack "a3", $disk->{ronameeven};
	$ret0 .= pack24($disk->{disksize});

	$ret0 .= pack "C", makecksumraw($ret0);

	my $ret1 = "";

	for (my $i = 0; $i < 82; $i++) {
		if ($i > scalar(@{$disk->{fsmap}->{lengths}}))
		{
			$ret1 .= pack24(0);
		} else {
			$ret1 .= pack24($disk->{fsmap}->{lengths}->[$i]);
		}
	}

	$ret1 .= pack24($disk->{l3sec2});
	$ret1 .= pack "a2SCC"
		, $disk->{ronameodd}
		, $disk->{diskid}
		, $disk->{opt4}
		, $disk->{fsmap}->{len3}
		; 

	$ret1 .= pack "C", makecksumraw($ret1);

	return $ret0 . $ret1;
}

sub readimage($) {
	my ($fn) = @_;

	my %ret = ();

	open(my $fh, "<:raw:", $fn) or die "Cannot open $fn: $!";


	#############################################################
	# sector 0
	#############################################################
	# 82 free space pointers
	my @free_starts = ();
	for (my $i = 0; $i < 82; $i++) {
		read24bit($fh, my $fs) or die "EOF reading sector 0";
		push @free_starts, $fs
	}
	$ret{fsmap}->{starts} = \@free_starts;

	read24bit($fh, $ret{l3sec1}) or die "EOF reading sector 0";
	readbytes($fh, 3, $ret{ronameeven}) or die "EOF reading sector 0";
	read24bit($fh, $ret{disksize}) or die "EOF reading sector 0";
	read8bit($fh, my $ck0) or die "EOF reading sector 0";

	my $ckc0 = makesec0cksum(\%ret);

	$ckc0 == $ck0 or die "Bad checksum sector 0 $ck0 |= $ckc0";

	$ret{disksize} >= 10 or die "Bad disk size!";

	#############################################################
	# sector 1
	#############################################################
	# 82 free space pointers
	my @free_lengths = ();
	for (my $i = 0; $i < 82; $i++) {
		read24bit($fh, my $fs) or die "EOF reading sector 0";
		push @free_lengths, $fs
	}
	$ret{fsmap}->{lengths} = \@free_lengths;
	
	read24bit($fh, $ret{l3sec2}) or die "EOF reading sector 0";
	readbytes($fh, 2, $ret{ronameodd}) or die "EOF reading sector 0";
	read16bit($fh, $ret{diskid}) or die "EOF reading sector 0";
	read8bit($fh, $ret{opt4}) or die "EOF reading sector 0";
	read8bit($fh, $ret{fsmap}->{len3}) or die "EOF reading sector 0";
	read8bit($fh, my $ck1) or die "EOF reading sector 0";

	my $ckc1 = makesec1cksum(\%ret);

	$ckc1 == $ck1 or die "Bad checksum sector 1 $ck1 |= $ckc1";

	#read rest of disk as Data
	my $ds = 256 * ($ret{disksize}-2);
	my $dat;
	my $l = read($fh, $dat, $ds);

	if ($l < $ds) {
		$dat .= "\0" x ($ds-$l);
	}

	# this is pants!

	my $interleave = 0;
	if ($fn =~ /\.(adf|adl)$/ && $ret{disksize} > 0x500)
	{
		print STDERR "WARNING: INTERLEAVE 16\n";
		$interleave = 16;	
	}
	
	$ret{interleave} = $interleave;


	#de-interleave the data if necessary
	if ($interleave) {
		my ($dat_a, $dat_b, $ptr, $n);
		$dat = ("\0" x 0x200) . $dat;

		length($dat) % ($interleave * 256 * 2) == 0 or die "Bad interleave";

		$n = int(length($dat) / ($interleave * 256 * 2));

		for (my $i = 0; $i < $n; $i++) {
			$dat_a .= substr($dat, $ptr, $interleave * 256);
			$ptr+=$interleave * 256;
			$dat_b .= substr($dat, $ptr, $interleave * 256);
			$ptr+=$interleave * 256;
		}

		$dat = substr($dat_a . $dat_b, 0x200);

	}

	$ret{data} = $dat;

	close($fh);

	return \%ret;
}

sub saveimage($$) {
	my ($disk, $filename) = @_;

	open (my $fh, ">:raw:", $filename) or die "Cannot write disk image $filename : $!";

	print $fh packfsmap($disk);


	my $interleave = $disk->{interleave};
	my $dat = $disk->{data};
	#re-interleave the data if necessary
	if ($interleave) {

		print STDERR "INTERLEAVE $interleave\n";

		my ($dat_a, $dat_b, $ptr, $n);
		$dat = ("\0" x 0x200) . $dat;


		length($dat) % ($interleave * 256 * 2) == 0 or die "Bad interleave";

		$n = int(length($dat) / ($interleave * 256 * 2));
		$dat_a = substr($dat, 0, $n * 256 * $interleave);
		$dat_b = substr($dat, $n * 256 * $interleave);

		$dat = "";
		$ptr = 0;
		for (my $i = 0; $i < $n; $i++) {
			$dat .= substr($dat_a, $ptr, $interleave * 256);
			$dat .= substr($dat_b, $ptr, $interleave * 256);

			$ptr += $interleave * 256;
		}

		$dat = substr($dat, 0x200);


	}

	print $fh $dat;

	close $fh;
}

sub debuginfo($) {
	my ($disk) = @_;

	print "FREESPACEMAP[\n";
	for (my $i = 0; $i < int($disk->{fsmap}->{len3} / 3); $i++) {
		my $s = $disk->{fsmap}->{starts}->[$i];
		my $l = $disk->{fsmap}->{lengths}->[$i];
		printf("%4d : %06X+%06X=%06X\n", $i, $s, $l, $s+$l);
	}
	print "]\n";
	printf "DISKSIZE=%06X %dK\n", $disk->{disksize}, ($disk->{disksize}*256)/1024;
	printf "OPT4=%1X\n", $disk->{opt4};

}

sub readdirent($) {
	my $fh = $_[0];
	my %ret = ();
	my $flags = 0;
	my $name = "";
	readbytes($fh, 10, my $nameandflags) or die "Error reading directory entry";
	#decipher name and flags
	my $l = -1;
	for (my $i = 0; $i <= 9; $i++) {
		my $c = ord(substr($nameandflags, $i, 1));
		$name .= chr($c & 0x7F);
		$flags = $flags >> 1;
		$flags = $flags | (($c & 0x80)?0x200:0);
		$c = $c & 0x7F;
		if ($l == -1 && ($c == 0x0d || $c == 0x00))
		{
			$l = $i;
		}
	}
	if ($l >= 0)
	{
		$name = substr($name, 0 , $l);
	}
	$ret{name} = $name;
	$ret{flags} = $flags;
	read32bit($fh, $ret{load}) or die "Error reading directory entry";
	read32bit($fh, $ret{exec}) or die "Error reading directory entry";
	read32bit($fh, $ret{length}) or die "Error reading directory entry";
	read24bit($fh, $ret{sector}) or die "Error reading directory entry";
	read8bit($fh, $ret{seq}) or die "Error reading directory entry";

	return \%ret;
}

sub packdirent($) {
	my ($ent) = @_;

	my $nameandflags="";
	my $mask = 0x01;

	my $n = notopbit($ent->{name});

	for (my $i = 0; $i <= 9; $i++) {

		$nameandflags .= chr(ord(substr($n, $i, 1)) | (($ent->{flags} & $mask)?0x80:00));

		$mask = $mask << 1;
	}

	return pack("a10LLLCCCC"
		, $nameandflags
		, $ent->{load}
		, $ent->{exec}
		, $ent->{length}
		, $ent->{sector}
		, $ent->{sector} >> 8
		, $ent->{sector} >> 16
		, $ent->{seq}
		)
}


sub safestr($) {
	my ($str) =@_;
	for (my $i = 0; $i < length($str); $i++) {
		my $c = substr($str, $i, 1);
		if (ord($c) < 32 || ord($c) > 127) {
			printf "\\x%02X", ord($c);
		}
		else {
			print $c;
		}
	}
}

sub notopbit($) {
	my $str = $_[0];
	my $ret = "";
	for my $i (0..length($str)-1) {
		my $c = ord(substr($str, $i, 1));
		$ret .= chr($c & 0x7F);
	}
	return $ret;
}

sub unpackdir($$$) {
	my ($disk, $sector, $name) = @_;

	$sector >= 2 || $sector <= $disk->{disksize} - 5 or die "Directory index out of bounds [$sector] [$name]";

	my $dirdata = read_data($disk, $sector, 5 * 256);

	my $ll = length($dirdata);
	$ll == 0x500 or die sprintf "Error reading directory %s [%06X] data truncated = %08X", $name, $sector, $ll;

	return unpackdir_int($disk, $sector, $name, $dirdata);
}

sub unpackdir_int($$$$) {
	my ($disk, $sector, $name, $dirdata) = @_;

	#open the directory data as a file
	open(my $fh, "<:raw:", \$dirdata) or die "Cannot read directory as string [$sector] [$name]";


	my %ret = ();

	$ret{sector} = $sector;
	read8bit($fh, $ret{seq}) or die "Error reading directory [$sector] 1 [$name]";
	readbytes($fh, 4, my $hugo1) or die "Error reading directory [$sector] 2 [$name]";

	$hugo1 eq "Hugo" or die "Not Hugo! (0) : " . safestr($hugo1) . "[$sector] [$name]";

	my @dirents = ();
	my $n = 47;
	for (my $i = 0; $i < 47; $i++) {
		my $dirent = readdirent($fh);
		push @dirents, $dirent;		

		if ($n > $i && !length($dirent->{name}))
		{
			$n = $i;
		}
	}

	splice(@dirents, $n);
	$ret{entries} = \@dirents;
	$ret{length} = $n;


	my $rawname;
	my $rawtitle;
	my $x;
	read8bit($fh, $x) or die "Error reading directory [$sector] 3 [$name]";
	$x == 0 or die "Unexpected value $x at offset 4CB in directory [$sector] 4 [$name]";
	readbytes($fh, 10, $rawname) or die "Error reading directory [$sector] 5 [$name]";
	read24bit($fh, $ret{parent}) or die "Error reading directory [$sector] 6 [$name]";
	readbytes($fh, 19, $rawtitle) or die "Error reading directory [$sector] 7 [$name]";
	readbytes($fh, 14, $x) or die "Error reading directory [$sector] 8 [$name]";
	$x eq "\0" x 14 or die "Unexpected stuff in resereved 4EC [$sector] 9 [$name]";

	read8bit($fh, my $seq2) or die "Error reading directory";
	readbytes($fh, 4, my $hugo2) or die "Error reading directory [$sector] 10 [$name]";

	read8bit($fh, $x) or die "Error reading directory [$sector] 14 [$name]";
	$x == 0 or die "Unexpected value $x at offset 4FF in directory [$sector] 15 [$name]";


	$hugo2 eq "Hugo" or die "Not Hugo! (2) : " . safestr($hugo2) . " [$sector] 11 [$name]";
	$seq2 == $ret{seq} or die "Mismatched sequence numbers $seq2 != $ret{seq} [$sector] 12 [$name]";

	$ret{name} = notopbit($rawname);
	$ret{name} =~ s/[\r\n\0].*//;
	$ret{title} = notopbit($rawtitle);
	$ret{title} =~ s/[\r\n\0].*//;

	close $fh;

	return \%ret;
}

sub packdir($) {
	my ($dir) = @_;
	my $ret = pack("Ca4", $dir->{seq}, "Hugo");

	for (my $i = 0; $i < 47; $i++) {
		$ret .= packdirent($dir->{entries}->[$i]);
	}

	$ret .= pack("xa10CCCa19x14Ca4x"
		, $dir->{name}
		, $dir->{parent}
		, $dir->{parent} >> 8
		, $dir->{parent} >> 16
		, $dir->{title}
		, $dir->{seq},
		, "Hugo"
		)
}

sub createdir_bytes($$$$$) {
	my ($disk, $parentdir, $sector, $name, $title) = @_;

	my $seq = 0;

	my $parentsector = ($parentdir->{sector})?$parentdir->{sector}:0;

	my $ret = pack(
		"CA4x1223a10CCCa19x14CA4x"
		,
		$seq,
		"Hugo",
		$name . chr(13),
		$parentsector,
		$parentsector >> 8,
		$parentsector >> 16,
		$name . chr(13),
		$seq,
		"Hugo"
		);
	return $ret;
}

sub finddir($$$) {
	my ($disk, $pathname, $create) = @_;

	$pathname =~ s/^\$\.//;

	my $dir = unpackdir($disk, 0x02, "\$.");

	if ($pathname eq "") {
		return $dir;
	} else {
		return finddir_int($disk, $dir, "\$.", $pathname, $create);
	}

}

sub finddir_int($$$$$) {
	my ($disk, $dir, $parent, $pathname, $create) = @_;

	my @comps = map { ($_ eq "") ? () : $_ } split(/\./, $pathname);
	if (scalar @comps == 0)
	{
		return $dir;
	}
	my $here = @comps[0];
	my $rest = join('.', @comps[1..$#comps]);

	my $herepath = "$parent$here.";

	#look for entry in current directory
	for my $d (@{$dir->{entries}}) {

		if (uc $d->{name} eq uc $here) {
			if (!($d->{flags} & FLAG_D)) {
				die "$pathname.$here is a file - trying to access as a directory";
			} elsif ($rest ne "") {
				return finddir_int($disk, unpackdir($disk, $d->{sector}, $herepath), $herepath, $rest, $create);
			} else {
				return unpackdir($disk, $d->{sector}, "$herepath");
			}
		}
	}

	if ($create) {
		# if we got to here then it didn't exist;
		my $cd = createdir_int($disk, $dir, $parent, $here);
		if ($rest ne "") {
			return finddir_int($disk, $cd, $herepath, $rest, $create);
		} else {
			return $cd;
		}
	} else {
		return undef;
	}


}

sub createdir_int($$$$) {
	my ($disk, $dir, $parent, $name) = @_;

	my $sector = alloc_space($disk, 0x05);	
	
	$sector >= 0 || die "Disk full : creating $parent.$name";

	if ($dir) {
		$dir->{length} >= 47 && die "Directory full [$parent]";

		# make directory entry
		# find where to insert
		my $ix = 0;
		while (
			($ix < scalar @{$dir->{entries}})
			&& uc $dir->{entries}->[$ix]->{name} lt $name) 
		{
			$ix++;		
		}

		# insert directory entry
		splice (@{$dir->{entries}}, $ix, 0, 
				({
					name => $name, 
					load => 0, 
					exec => 0, 
					length => 0x500,
					flags => FLAG_D | FLAG_R | FLAG_L,
					sector => $sector,
					seq => 0 
				})
			);

		$dir->{length}++;
		$dir->{seq}++;

		#create new directory and write back
		my $d = createdir_bytes($disk, $dir, $sector, $name, $name);
		write_data($disk, $sector, 0x0500, $d);
	}


	#write back updated directory
	write_data($disk, $dir->{sector}, 0x0500, packdir($dir));

	my $r = unpackdir($disk, $sector, $name);

	return $r;

}

sub savefile2img($$$$$$$$$) {
	my ($disk, $dir, $adfspath, $adfsname, $load, $exec, $access, $orgfullpath, $overwrite) = @_;

	open(my $fh, "<:raw:", $orgfullpath) or die "Cannot open file $orgfullpath : $!";
	my $filedata = do { local $/; <$fh> };
	close $fh;

	my $sector = alloc_space($disk, (length($filedata) == 0)?1:int((length($filedata) + 255)/256));	
	$sector >= 0 || die "Disk full : creating $adfspath$adfsname";

	# find where to insert
	my $ix = 0;
	while (
		($ix < scalar @{$dir->{entries}})
	     && (uc($dir->{entries}->[$ix]->{name}) lt uc($adfsname))
	     ) {
	     	#printf "%s < %s\n", uc($dir->{entries}->[$ix]->{name}), uc($adfsname);
		$ix++;		
	}

	$ix < scalar @{$dir->{entries}} && uc $dir->{entries}->[$ix]->{name} eq uc $adfsname && die "File $adfspath$adfsname already exists";

	# insert directory entry
	splice (@{$dir->{entries}}, $ix, 0, 
			({
				name => $adfsname, 
				load => $load, 
				exec => $exec, 
				length => length($filedata),
				flags => $access,
				sector => $sector,
				seq => 0 
			})
		);

	$dir->{length}++;
	$dir->{seq}++;

	#write back updated directory
	write_data($disk, $dir->{sector}, 0x0500, packdir($dir));

	#write file data
	write_data($disk, $sector, length($filedata), $filedata);

}


sub write_data($$$$) {
	my ($disk, $sector, $length, $data) = @_;

	my $length2 = int(($length + 255)/256) * 256;

	$disk->{data} = substr($disk->{data}, 0, ($sector - 2) * 256) . pack("a$length2", $data) . substr($disk->{data}, $length2 + ($sector - 2) * 256);

}

sub read_data($$$) {
	my ($disk, $sector, $length) = @_;

	return substr($disk->{data}, ($sector - 2) * 256, $length);
}

sub alloc_space($$) {
	my ($disk, $nsectors) = @_;


	#search free space map for an entry large enough
	for (my $i = 0; $i < int($disk->{fsmap}->{len3} / 3); $i++) {
		my $len = $disk->{fsmap}->{lengths}->[$i];
		my $start = $disk->{fsmap}->{starts}->[$i];

		if ($len > $nsectors) {
			$disk->{fsmap}->{lengths}->[$i] -= $nsectors;
			$disk->{fsmap}->{starts}->[$i] += $nsectors;

			return $start;
		} elsif ($len == $nsectors) {
			for (my $j = $i; $j < int($disk->{fsmap}->{len3} / 3) - 1; $j++) {
				$disk->{fsmap}->{lengths}->[$j] = $disk->{fsmap}->{lengths}->[$j + 1];
				$disk->{fsmap}->{starts}->[$j] = $disk->{fsmap}->{starts}->[$j + 1];
			}
			$disk->{fsmap}->{len3} -= 3;
			return $start;
		}
	}

	return -1;


}

sub flags2str($) {
	my ($flags) = @_;
	my $ret;
	for (my $i = 9; $i >=0; $i--)
	{
		$ret .= ($flags & (1 << $i))?substr($FLAGNAMES, $i, 1):"-";

	}
	return $ret;
}

sub debuginfodir($) {
	my ($dir) = @_;

	printf "DIR: %10s [%19s]\n", $dir->{name}, $dir->{title};

	for (my $i = 0; $i < $dir->{length}; $i++) {
		
		printf "  %3X %10s %08X %08X %08X %06X %s\n"
			, $dir->{entries}->[$i]->{flags}
			, flags2str($dir->{entries}->[$i]->{flags})
			, $dir->{entries}->[$i]->{load}
			, $dir->{entries}->[$i]->{exec}
			, $dir->{entries}->[$i]->{length}
			, $dir->{entries}->[$i]->{sector}
			, $dir->{entries}->[$i]->{name};
	}
}


sub treedump($$$) {
	my ($disk, $dir, $parname) = @_;

	my $prefix = "$parname.$dir->{name}";
	for my $ent (@{$dir->{entries}}) {
		if ($ent->{flags} & FLAG_D) {
			printf "====%06X%====\n", $ent->{sector};
			treedump($disk, unpackdir($disk, $ent->{sector}, "$parname.$ent->{name}"), $prefix);
		} else {
			print "$prefix.$ent->{name}\n";
		}
	}


}


#munge a adfs file spec (with wildcards) to a regex matching string
sub spec2re($) {
	my ($spec) = @_;

	my $ret = "";

	for my $c (split(//, $spec)) {
		if ($c =~ /[\Q$BADSPECCHARS\E]/) {
			return "";
		} elsif ($c eq "#") {
			$ret .= ".";
		} elsif ($c eq "*") {
			$ret .= ".*?";
		} elsif ($c eq ".") {
			$ret .= "\\.";
		} else {
			$ret .= "\Q$c\E";
		}

	}

	$ret =~ s/\\\.\\%\\\./(\.[^.]+)+\./;

	$ret = "$ret";

	return $ret;
}


sub spec2repath($) {
	my ($spec) = @_;
	my $ret = "";

	$spec =~ s/^\$\.//;

	for my $s (split(/\./, $spec)) {
		if ($s eq "")
		{
			$ret .= "\\.";
		} elsif ($s eq "%") {
			$ret .= "(\\.[^.]+)+";
		} else {
			$ret .= spec2re($s);
		}
	}

	$ret .= "\\.";

	return "^\\\$\\.$ret";
}


#returns true false if any matched and 3rd argument is out
#array of direntsmatches i.e. {path =>, dirent =>}
#the path is the path to the directory containing the dirent
#returns -1 if a bad filespec is encountered, 0 if no matches
#!=0 for matches
sub finddirents($$$) {
	my ($disk, $spec) = @_;
	my $dir = unpackdir($disk, 0x2, "\$");

	return finddirents_int($disk, $dir, $spec, "\$.", $_[2]);
}

sub finddirents_int($$$$$) {
	my ($disk, $dir, $spec, $parpath) = @_;


	my @specs = split(/\./, $spec);
	my $spechere = @specs[0];
	my $specrest = join('.', splice(@specs, 1));

	my $ret = 0;

	if ($spechere eq "")
	{
		return -1; #.. found
	}

	if ($spechere eq "\$") {
		if ($specrest ne "") {
			return finddirents_int($disk, unpackdir($disk, 0x2, "\$"), $specrest, "\$.", $_[4]);
		} else {
			$_[4] = [{ path => "", dirent => $ROOTDIRENT } ];
			return 1
		}
	}
	elsif ($spechere eq "^")
	{
		if ($dir->{name} eq "\$") {
			#ADFS doesn't seem to do this - instead returns "Broken directory"
			return finddirents_int($disk, unpackdir($disk, 0x2, "\$"), $specrest, "\$.", $_[4]);
		} else {			
			my $pd = $parpath;
			$pd =~ s/^(.*?)\.[^\.]+$/\1/;
			return finddirents_int($disk, unpackdir($disk, $dir->{parent}, $parpath), $specrest, "$pd.", $_[4]);
		}
	} 
	elsif ($spechere eq "%")
	{
		if ($specrest)
		{
			my $r = finddirents_int($disk, $dir, $specrest, "$parpath", $_[4]);
			if ($r < 0) {
				return $r;
			} else {
				$ret += $r;
			}
		}
		for my $d (@{$dir->{entries}}) {
			if ($d->{flags} & FLAG_D) {
				if ($specrest) {
					my $r = finddirents_int($disk, unpackdir($disk, $d->{sector}, "$parpath$d->{name}"), $spec, "$parpath$d->{name}.", $_[4]);
					if ($r < 0) {
						return $r;
					} else {
						$ret += $r;
					}
				} else {
					push @{$_[4]}, {path => $parpath, dirent => $d};
				}
			}
		}

	}
	elsif ($specrest) {
		# non-leaf - look for directories

		my $specherere = "^" . spec2re($spechere) . "\$";

		for my $d (@{$dir->{entries}}) {
			if (($d->{name} =~ /$specherere/i) && ($d->{flags} & FLAG_D)) {
				my $r = finddirents_int($disk, unpackdir($disk, $d->{sector},"$parpath$d->{name}"), $specrest, "$parpath$d->{name}.", $_[4]);		
				if ($r < 0) {
					return $r;
				} else {
					$ret += $r;
				}
			}
		}
	} else {
		# leaf match any objects

		my $specherere = spec2re($spechere);

		for my $d (@{$dir->{entries}}) {
			if ($d->{name} =~ /$specherere/i) {
				push @{$_[4]}, {path => $parpath, dirent => $d};
			}
		}
	}

}


sub ensuredosdir($$) {
	my ($base, $rest) = @_;

	my $ret = $base;

	my @subdirs = split(/\./, $rest);
	for my $d (@subdirs) {
		if ($d ne "") {
			my $dosdir = safeDOSUnixPath($d);
			$ret = File::Spec->catdir($ret, $dosdir);
			if (!-d $ret) {
				if (-e $ret) {
					die "Cannot create directory $ret - there is already a file with that name";
				} else {
					make_path($ret);
					# make a .inf file 
					open (my $fhi, ">", "$ret.inf") or die "Cannot create .inf file $ret.inf $!";
					printf $fhi "%-12s 00000000 00000000 00000000 0D\n", $d;
					close $fhi;
				}
			}
		}
	}

	return $ret;
}

sub Usage() {
	print STDERR "

	adf <command> [option...] <imagename> [<filespec>...]

command = info:
	Displays a listing of directory contents, <filespec> contains a file
	and directory spec to match. If there are multiple filespecs then
	all files and directories matching will be returned

	Options:
		-n|--names - will only display file names instead of full info
		-f|--files - will only display matching files (not directories)

	EXAMPLES:
	
	\$ adf info cf11.adf %.ROMS.ADFS*

	Will search the entire disk for any directory \"ROMS\" and return any files
	within that directory (or any contained directory) for files starting \"ADFS\"

	\$ adf info dom.adl %.*/adl

	Will search the entire disk for any files ending \"/adl\"

	\$ adf info dom.adl %.*/adl %.*/adf

	Will search the entire disk for any files ending \"/adl\" or \"/adf\"

	\$ adf info dom.adl $.src.%.h.*

	Will search the entire src directory tree for any files in directories
	named \"h\" at whatever level.

command = read:
	-d|--dest followed by a directory name. This switch is mandatory the 
		directory must exist it must be empty
	-x|--excludedirs the given directory prefix will be removed before
		any directories in the output. The special prefix @ indicates
		find the smallest common root.
	-f|--flatten don't create directories in the output, files with a 
		similar name will be given a .NNN suffix

	By default the full directory tree from the root of the image will
	be recreated in the destiation directory. i.e. if the following 
	files are matched:

	$.DATA.ROMS.Acorn.WORDW
	$.DATA.ROMS.Dom.Willy
	$.DATA.PROGS.Bob.Worms

	were matched and the destination directory is ./dump the following
	file will be created:

	./dump/DATA/ROMS/Acorn/WORDW
	./dump/DATA/ROMS/Dom/Willy
	./dump/DATA/PROGS/Bob/Worms

	if -x $.DATA.ROMS is specified then:

	./dump/Acorn/WORDW
	./dump/Dom/Willy
	./dump/DATA/PROGS/Bob/Worms

	if -x $.DATA.ROMS -x $.DATA.PROGS is specified then:

	./dump/Acorn/WORDW
	./dump/Dom/Willy
	./dump/Bob/Worms

	if -x @ then:

	./dump/ROMS/Acorn/WORDW
	./dump/ROMS/Dom/Willy
	./dump/PROGS/Bob/Worms

command = add
	-d|--dest followed by an ADFS directory name. The default is \$
		if the destination directory doesn't exist it will be
		created (recursively)
	-x|--excludedirs the given directory prefix will be removed
		from source filenames before translation to ADFS paths
		the special prefix @ will exclude the largest common
		prefix directory
	-f|--flatten the source directory names will be ignored
	-o|--overwrite overwrite files in the image. If this switch
		is not specified then existing files will not be 
		overwritten

	.inf files can be used for both file and directory names if no 
	.inf file is specified then a default translation will be used to 
	create names that are compatible with ADFS

command = form
	-s|--size The size of the image format to produce, it can be one
		of the following codes or a size NNN followed by K or M
		For sizes S/M/L the size will be defaulted depending on 
		the exension of the image name. For all sizes except L 
		the default will be to not interleave the sides. If 
		interleaved sides are required for other sizes the -i 
		switch must be used

	Code  Name     Organisation       Ext
	-----+--------+------------------+-----+-----------------------------
	  S  | small  | single sided 40T | ads | 160K
	  M  | medium | single sided 80T | adm | 320K
	  L  | large  | double sided 80T | adl | 640K (sides interleaved)

	-i|interleave The data will be interleaved such that 16 sectors of 
		side side 0 are followed by 16 sectors of side 1. The image
		size must be a multiple of 2*16*256=8k. This is the default
		for images with a name .adl, all .adl files are interleaved

	i.e.

	adl.pl form small.ads [will create a 160K disk]
	adl.pl form -s 320M disc0.dat [will create a 320 megabyte hard disk]
	adl.pl form -s 1024K silly.adl [will create a 1 megabyte interleaved disk]
	adl.pl form -i -s 800K silly.adf [will create an 800k interleaved disk]
	adl.pl form -s 800K silly.adf [will create an 800k non-interleaved disk]

Note: be careful about wildcards and whatever environment you are running in you
may need to quote the strings with wildcards and \$ signs depending on if you're 
running in a *nix or DOS environment. i.e. in bash:

$ ./adf.pl info x.adf * 

would expand to have the names of files in the current directory in place of the *

$ /adf.pl info x.adf '*'

would be better

";
}

sub command_form(@) {

	my @args = @_;
	my $size = -1;
	my $interleave = 0;

	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-s" || $switch eq "--size")
		{
			$size == -1 or die "Two sizes specified";
			my $sizestr = shift @args or die "Missing size parameter";
			$sizestr = uc($sizestr);
			if ($sizestr eq "S") {
				$size = 40 * 256 * 16;
			} elsif ($sizestr eq "M") {
				$size = 80 * 256 * 16;
			} elsif ($sizestr eq "L") {
				$size = 80 * 256 * 16 * 2;
				$interleave = 16;
			} elsif ($sizestr =~ /^([0-9]+)(M|K)?/) {
				$size = $1;
				if ($2 eq "M") {
					$size = $size * 1024 * 1024;
				} elsif ($2 eq "K") {
					$size = $size * 1024;
				}

				$size >= 0x700 or die "Too small!";

			} else {
				die "Unrecognised size $size";
			}

		} 
		elsif ($switch eq "-i" || $switch eq "--interleave")
		{
			$interleave = 16;
		} else {		
			die "Unrecognised switch \"$switch\"";
		}
	}

	my $imagename = shift @args or die "Missing image filename";

	if ($imagename =~ /.adl$/i)
	{
		$interleave = 16;
		if ($size == -1)
		{
			$size = 80 * 16 * 256 * 2;
		}
	} elsif ($imagename =~ /.adm$/i && $size == -1) {
		$size = 80 * 256 * 16;
	} elsif ($imagename =~ /.ads$/i && $size == -1) {
		$size = 40 * 256 * 16;
	}

	$size == -1 && die "Size not specified";

	$interleave && ($size % (16 * 256 * 2)) != 0 && die "Interleaved disks must be a multiple of 8k long";

	print "$size $interleave\n";

	my $disk = format_disk($size, $interleave);

	saveimage($disk, $imagename);

}



sub command_info(@) {

	my @args = @_;
	my $sw_names = 0;
	my $sw_files = 0;

	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-n" || $switch eq "--names")
		{
			$sw_names = 1;
		} elsif ($switch eq "-f" || $switch eq "--files")
		{
			$sw_files = 1;
		} else {		
			die "Unrecognised switch \"$switch\"";
		}
	}

	my $imagename = shift @args or die "Missing image filename";

	my $disk = readimage($imagename);

	my %all = ();

	my @specs = @args;

	if (!scalar @specs) {
		push @specs, "$.*";
	}

	while (my $filespec = shift @specs) {

		my $dps;
		my $c = finddirents($disk, $filespec, $dps);
		$c < 0 and die "Bad filespec $filespec";		

		for my $dp (@{$dps}) {
			my $fullname = "$dp->{path}$dp->{dirent}->{name}";
			$all{$fullname} = $dp;
		}
	}

	my $lastp = "";
	for my $k (sort { 
		uc $all{$a}->{path} cmp uc $all{$b}->{path} 
		|| uc $all{$a}->{dirent}->{name} cmp uc $all{$b}->{dirent}->{name}
		} keys %all) {
		my $dp = $all{$k};

		if ($sw_files == 0 || !($dp->{dirent}->{flags} & FLAG_D)) {
			if ($sw_names) {
				print "$dp->{path}$dp->{dirent}->{name}\n";
			} else {
				if ($lastp eq "" || $lastp ne $dp->{path}) {
					print "[$dp->{path}]\n";
					$lastp = $dp->{path};
				}
				printf "%-10s %9s (%2d)  %08X  %08X  %08X  %06X\n"
					, $dp->{dirent}->{name}
					, flags2str($dp->{dirent}->{flags})
					, $dp->{dirent}->{seq}
					, $dp->{dirent}->{load}
					, $dp->{dirent}->{exec}
					, $dp->{dirent}->{length}
					, $dp->{dirent}->{sector};			
			}
		}


	}

}

sub is_folder_empty($) { 
	my $dirname = shift; 
	opendir(my $dh, $dirname) or die "Not a directory"; 
	return scalar(grep { $_ ne "." && $_ ne ".." } readdir($dh)) == 0; 
}

sub begins_with
{
    return substr($_[0], 0, length($_[1])) eq $_[1];
}

sub command_read(@) {

	my @args = @_;
	my $destdir = "";
	my @excludedirs = ();
	my $excludecommon = 0;
	my $flatten = 0;

	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-d" || $switch eq "--dest") {
			$destdir = shift @args or die "Missing destination directory name";
		} elsif ($switch eq "-x" || $switch eq "--excludedirs") {
			my $e = shift @args or die "Missing excludedirs";
			if ($e eq "@") {
				$excludecommon = 1;
			} else {
				push @excludedirs, $e;
			}
		} elsif ($switch eq "-f" || $switch eq "--flatten") {
			$flatten = 1;
		} else {
			die "Unrecognised switch \"$switch\"";
		}
	}

	$destdir or die "You must specify a destination directory";
	
	if (! -d $destdir) {
		die "$destdir doesn't exist";
	}
	if (!is_folder_empty($destdir)) {
		die "$destdir isn't empty";
	}

	my $imagename = shift @args or die "Missing image filename";

	my $disk = readimage($imagename);

	my %all = ();

	while (my $filespec = shift @args) {


		my $dps;
		my $c = finddirents($disk, $filespec, $dps);
		$c < 0 and die "Bad filespec \"$filespec\"";		

		for my $dp (@{$dps}) {
			my $fullname = "$dp->{path}$dp->{dirent}->{name}";
			$all{$fullname} = $dp;
		}
	}

	my $commonroot = "";
	for my $k (sort keys %all) {
		my $p = $all{$k}->{path};
		if ($commonroot eq "") {
			$commonroot = $k;
		} elsif (!($p =~ /^\Q$commonroot\E.*/i)) {
			my $l = 1;
			while (
				$l < length($commonroot) && 
				$l < length($p) && 
				uc substr($commonroot, 0, $l) eq uc substr($p, 0, $l)
				) {
				$l++;
			}
			$commonroot = substr($commonroot, 0, $l);
		}
	}

	$commonroot =~ s/^(([^.]+\.)+)[^.]+$/\1/; #remove partial directory names


	my $lastp = "";
	for my $k (sort keys %all) {
		my $dp = $all{$k};

		if (!($dp->{dirent}->{flags} & FLAG_D)) {

			my $path = $dp->{path};

			my $rest;

			if ($flatten) {
				$rest = "";
			} else {
				$rest = $path;

				for my $e (@excludedirs) {
					my $rest2;
					if (matchpath($path, $e, $rest2)) {
						if (length($rest) > length($rest2))
						{
							$rest = $rest2;
						}
					}

				}

				if ($excludecommon && length($rest) > length($path) - length($commonroot)) {
					$rest = substr($path, length($commonroot));
				}

				$rest =~ s/^\$\.//;
			}

			my $dir = ensuredosdir($destdir, $rest);

			my $safefn = safeDOSUnixFilename($dp->{dirent}->{name});
			my $fn = File::Spec->catfile($dir, $safefn);
			my $ctr = 0;
			my $suf = "";
			while (-e "$fn$suf") {
				$ctr++;
				$suf = sprintf(".%03d", $ctr);
				$ctr >= 1000 and die "Cannot create a unique name;"
			}

			$fn = "$fn$suf";


			open (my $fho, ">:raw:", $fn) or die "Cannot open $fn for output $!";

			print $fho read_data($disk, $dp->{dirent}->{sector}, $dp->{dirent}->{length});

			close $fho;

			# make .inf filespec

			open (my $fhi, ">", "$fn.inf") or die "Cannot open $fn.inf for output $!";

			printf $fhi "%-12s %08X %08X %08X %02X\n"
				, $dp->{dirent}->{name}
				, $dp->{dirent}->{load}
				, $dp->{dirent}->{exec}
				, $dp->{dirent}->{length}
				, $dp->{dirent}->{flags}
				;

			close $fhi;

		}


	}

}

sub command_add(@) {
	my @args = @_;

	my $destdir = "\$";

	my @excludedirs = ();
	my $excludecommon = 0;
	my $flatten = 0;
	my $overwrite = 0;

	my $dirsep = File::Spec->catdir('','');


	while (@args[0] =~ /^-/) {
		my $switch = shift @args;

		if ($switch eq "-d" || $switch eq "--dest") {
			$destdir = shift @args or die "Missing destination directory name";
		} elsif ($switch eq "-x" || $switch eq "--excludedirs") {
			my $e = shift @args or die "Missing excludedirs";
			if ($e eq "@") {
				$excludecommon = 1;
			} else {
				$e =~ s/^(.*?)$dirsep+/\1/;
				push @excludedirs, $e;
			}
		} elsif ($switch eq "-f" || $switch eq "--flatten") {
			$flatten = 1;
		} elsif ($switch eq "-o" || $switch eq "--overwrite") {
			$overwrite = 1;
		} else {
			die "Unrecognised switch \"$switch\"";
		}
	}

	$destdir or die "You must specify a destination directory";
	
	$destdir =~ s/([^\.])$/\1./;

	my $imagename = shift @args or die "Missing image filename";

	my $disk = readimage($imagename);

	my %all = ();

	FILESPEC: while (my $filespec = shift @args) {

		if (-d $filespec) {
			printf STDERR "WARNING: ignoring directory $filespec\n";
			next FILESPEC;
		} elsif (!-e $filespec) {
			die "FILE $filespec doesn't exist";
		} else {

			my $skip = 0;
			my $inf;

			if ($filespec =~ /(.*?)(\.inf|\.INF)$/) {
				if ( -e "$1") {
					$inf = $filespec;
					$filespec = $1;
					if (-d $filespec) {
						printf STDERR "WARNING: ignoring directory $filespec\n";
						next FILESPEC;
					}
				}
			} elsif (-e "$filespec.inf") {
				$inf = "$filespec.inf";
			} elsif (-e "$filespec.INF") {
				$inf = "$filespec.INF";
			}

			if (exists $all{$filespec})
			{
				$skip = 1;
			}

			my ($fn, $p) = fileparse($filespec);

			if (!$skip) {
				$all{$filespec} = { 
					orgdir => $p, 
					orgfilename => $fn, 
					orgfullpath => $filespec, 
					adfsname => substr(safeADFSfilename($fn),0,12),
					load => 0,
					exec => 0,
					access => FLAG_W | FLAG_R					
				};

				if ($inf ne "") {
					open (my $fhi, "<", $inf) or die "Cannot open $inf : $!";
					my $l = <$fhi>;

					decodeinf($l, $all{$filespec});
				}
			}

		}
	}


##	for my $k (sort keys %all) {
##		print "$k: ";
##		for my $k2 (keys %{$all{$k}}) {
##			my $v = $all{$k}->{$k2};
##			print "$k2 => $v "
##		}
##		print "\n";
##	}
##

	my $commonroot = "";
	for my $k (sort keys %all) {
		my $p = $all{$k}->{orgdir};
		if ($commonroot eq "") {
			$commonroot = $k;
		} elsif (!($p =~ /^\Q$commonroot\E.*/i)) {
			my $l = 1;
			while (
				$l < length($commonroot) && 
				$l < length($p) && 
				uc substr($commonroot, 0, $l) eq uc substr($p, 0, $l)
				) {
				$l++;
			}
			$commonroot = substr($commonroot, 0, $l);
		}
	}

	(my $_x, $commonroot) = fileparse($commonroot);
	$commonroot =~ s/^(.*?)\Q$dirsep\E+$/\1/;

	#remove unwanted prefixes

	if ($excludecommon) {
		push @excludedirs, $commonroot;
	}

	for my $k (sort keys %all) {

		my $f = $all{$k};
		my $p = $f->{orgdir};
		my $trimpre = undef;
		my $trimstuff = $p;

		for my $e (@excludedirs) {
			if ($p =~ /^(\Q$e\E)($|\Q$dirsep\E.*$)/) {
				my ($pre, $suf) = ($1, $2);
				$suf =~ s/^$dirsep+(.*)/\1/;
				if (!$trimpre || length($suf) < length($trimstuff)){
					$trimpre = $pre;
					$trimstuff = $suf;
				}
			}
		}


		$f->{trimpre} = $trimpre;
		$f->{trim} = $trimstuff;
	}

	# get a set of directories to create - these will contain the longest possible 
	# paths into the image

	# make a set of all directories that need to be created
	my %alldirs = ();
	my $prevpre;
	my $prevsuf;
	for my $f (sort { $b->{trimpre} . $b->{trim} cmp $a->{trimpre} . $a->{trim} } map { $all{$_} } keys(%all)) {
		my $pre = $f->{trimpre};
		my $suf = $f->{trim};
		if ( !begins_with($prevpre, $pre) || !begins_with($prevsuf, $suf) ) {
			my $x = "";
			for my $pp (split /\Q$dirsep\E/, $suf) {
				if ($pp ne "") {
					if ($x ne "")
					{
						$x = $x . "$dirsep" . $pp;
					} else {
						$x = $pp;
					}
				}
				$alldirs{"$pre|$x"}=1;
			}
		}
		$prevpre = $pre;
		$prevsuf = $suf;

	}

	my %pathmap = ();

	# check for .inf files or make default names
	for my $k (sort keys %alldirs) {
		$k =~ /^([^\|]+)\|((.*?\Q$dirsep\E)*)([^\Q$dirsep\E]+)$/ or die "BAD!";

		my $root = $1;
		my $b4 = $2;
		my $leaf = $4;

		my $leafadfs = substr(safeADFSfilename($leaf), 0, 10);

		my $path = "$root$dirsep$b4$leaf";
		my $pathb4 = "$root$dirsep$b4";
		my $inffn = $path . ".inf";

		if (-e $inffn) {
			open (my $fhinf, "<", $inffn) or die "Cannot open $inffn : $!";

			my $l = <$fhinf>;
			if ($l =~ /\s*([^\s]+)(\s+|$)/) {
				$leafadfs = striptopbit("$1");
			}

			close $fhinf;
		} 

		my $n = $pathmap{$pathb4} . $leafadfs . ".";
		$pathmap{"$path$dirsep"} = $n;

	}


	for my $k (sort keys %all) {

		print "$k => $destdir$pathmap{$all{$k}->{orgdir}}$all{$k}->{adfsdir}$all{$k}->{adfsname}\n";

		my $adfsdir = "$destdir$pathmap{$all{$k}->{orgdir}}$all{$k}->{adfsdir}";

		my $dir = finddir($disk, $adfsdir, 1);


		savefile2img(
			$disk, 
			$dir, 
			"$destdir$pathmap{$all{$k}->{orgdir}}", 
			$all{$k}->{adfsname}, 
			$all{$k}->{load}, 
			$all{$k}->{exec}, 
			$all{$k}->{access}, 
			$all{$k}->{orgfullpath}, 
			$overwrite);

	}

	saveimage($disk, $imagename);
}


sub matchpath($$$) {
	my ($path, $spec) = @_;

	my $spec_re = spec2repath($spec);	

	my $ret = $path =~ /($spec_re)(.*)$/i;
	if ($ret)
	{
		my $s = $1;
		my $r = $2;
		$_[2] = $r;
	}
	return $ret;
}

sub decodeinf($$) {
	my ($inf, $out) = @_;

	if ($inf =~ / ([^\s]+) (\s+ ([0-9A-F]{6,8}) (\s+ ([0-9A-F]{6,8}) (\s+
([0-9A-F]{6,8}) (\s+ ([0-9A-F]{2}) )? )? )? )?		/x) {
		
		$out->{adfsname} = $1;
		if ($3) {
			$out->{load} = hex($3);
		}
		if ($5) {
			$out->{exec} = hex($5);
		}
		if ($9) {
			$out->{access} = hex($9);
		}

		$out->{adfsname} =~ s/^\$\.//;
	}

	while ($out->{adfsname} =~ /^([^.]\.)(.*)/) {
		$out->{adfsdir} .= $1;
		$out->{adfsname} = $2;	
	}
}

sub safeDOSUnixFilename($) {
	my ($l) = @_;

	$l =~ tr/\?<>\/\\/#$^.@/;	#differs from JGH - \\ => @
	return $l;
}

sub safeADFSfilename($) {
	my ($l) = @_;

	$l =~ tr/\&#\$\^@%\./\+?<>=;\//;	
	return $l;	
}

sub striptopbit($) {
	my ($l) = @_;
	my $ret = "";
	for my $c (map { ord($_) } split (//, $l)) {
		$ret .= chr($c & 0x7F);
	}
	return $ret;
}


sub safeDOSUnixPath($) {
	my ($l) = @_;
	my $ret = "";

	for my $s (split(/\./, $l)) {
		if ($ret ne "") {
			$ret = File::Spec->catdir($ret, safeDOSUnixFilename($s));
		} else {
			$ret = safeDOSUnixFilename($s);
		}
	}
	return $ret;
}


#########################################################################################
# MAIN
#########################################################################################

my $command = shift or die "Missing command";

if ($command eq "info") {
	command_info(@ARGV);
} elsif ($command eq "read") {
	command_read(@ARGV);
} elsif ($command eq "add") {
	command_add(@ARGV);
} elsif ($command eq "form") {
	command_form(@ARGV);
} else {
	die "Unrecognised command \"$command\"";
}


#
#my $disk = readimage("test-images/cf11.dat");
#
#debuginfo($disk);
#
#my $rootdir = unpackdir($disk, 0x2);
#
#debuginfodir($rootdir);
#
##treedump($disk, $rootdir, "");
#
#my $spec = "ROMS.*.Apps.*wwis*";
#my $dps;
#my $c = finddirents($disk, $spec, $dps);
#$c < 0 and die "Bad filespec $spec";
#for my $d (@$dps) {
#	printf "[%s.]%s\n", $d->{path}, $d->{dirent}->{name};
#}