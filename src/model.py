# -*- coding: utf-8 -*-

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    create_engine,
    DateTime,
    event,
    exc,
    Integer,
    select,
    String
)

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql import func

from config import (
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_POOL_RECYCLE
)

Base = declarative_base()

engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    pool_recycle=SQLALCHEMY_POOL_RECYCLE,
    pool_pre_ping=True
)

session = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
)

session.expire_on_commit = False


class Device(Base):
    __tablename__ = 'device'
    id = Column(Integer, primary_key=True)
    dt = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    guid = Column(String(64), index=True, unique=False)
    type = Column(Integer, index=True, unique=False)
    proto = Column(Integer, index=True, unique=False)
    ip = Column(String(39), index=False, unique=False)
    country = Column(String(255), index=False, unique=False)
    city = Column(String(255), index=False, unique=False)
    conns = Column(Integer, index=False, unique=False)
    weight = Column(Integer, index=False, unique=False, server_default='1')
    bytesin = Column(BigInteger, index=False, unique=False)
    bytesout = Column(BigInteger, index=False, unique=False)
    status = Column(Integer, index=True, unique=False)
    cipher = Column(String(17), index=True, unique=False)
    auth = Column(String(15), index=True, unique=False)
    upnp = Column(Integer, index=True, unique=False)
    hostapd = Column(Integer, index=True, unique=False)

    def __init__(
        self,
        dt,
        guid,
        type,
        proto,
        ip,
        country,
        city,
        conns,
        weight,
        bytesin,
        bytesout,
        status,
        cipher,
        auth,
        upnp,
        hostapd
    ):
        self.dt = dt
        self.guid = guid
        self.type = type
        self.proto = proto
        self.ip = ip
        self.country = country
        self.city = city 
        self.conns = conns 
        self.weight = weight 
        self.bytesin = bytesin 
        self.bytesout = bytesout
        self.status = status
        self.cipher = cipher
        self.auth = auth
        self.upnp = upnp
        self.hostapd = hostapd


class Speedtest(Base):
    __tablename__ = 'speedtest'
    id = Column(Integer, primary_key=True)
    dt = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    guid = Column(String(64), index=True, unique=False)
    status = Column(Integer, index=True, unique=False)
    down = Column(String(255), index=False, unique=False)
    up = Column(String(255), index=False, unique=False)

    def __init__(self, dt, guid, status, down, up):
        self.dt = dt
        self.guid = guid
        self.status = status
        self.down = down
        self.up = up 


class IOtest(Base):
    __tablename__ = 'iotest'
    id = Column(Integer, primary_key=True)
    dt = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    guid = Column(String(64), index=True, unique=False)
    status = Column(Integer, index=True, unique=False)
    test = Column(Integer, index=True, unique=False)
    result = Column(String(255), index=False, unique=False)

    def __init__(self, dt, guid, status, test, result):
        self.dt = dt
        self.guid = guid
        self.status = status
        self.test = test
        self.result = result


class Sessions(Base):
    __tablename__ = 'sessions'
    id = Column(Integer, primary_key=True)
    ts = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    trackingid = Column(String(36), index=True, unique=False)
    provider = Column(String(50), index=True, unique=False)
    email = Column(String(50), index=True, unique=False)
    password = Column(String(50), index=False, unique=False)
    profile = Column(String(50), index=False, unique=False)
    switch_profile = Column(Boolean, index=False, unique=False)
    titleid = Column(Integer, index=True, unique=False)
    host = Column(String(255), index=True, unique=False)
    tag = Column(String(255), index=True, unique=False)
    tries = Column(Integer, index=False, unique=False)
    attempt = Column(Integer, index=False, unique=False)
    seconds = Column(Integer, index=False, unique=False)

    def __init__(
        self, ts, trackingid, provider, email, password, profile,
        switch_profile, titleid, host, tries, attempt, seconds
    ): 
        self.ts = ts
        self.trackingid = trackingid
        self.provider = provider
        self.email = email
        self.password = password
        self.profile = profile
        self.switch_profile = switch_profile
        self.titleid = titleid
        self.host = host 
        self.tag = tag 
        self.tries = tries 
        self.attempt = attempt 
        self.seconds = seconds


class Errors(Base):
    __tablename__ = 'errors'
    id = Column(Integer, primary_key=True)
    ts = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    session_id = Column(Integer, index=True, unique=False)
    exception = Column(String(50), index=True, unique=False)
    mdelay = Column(Integer, index=False, unique=False)
    mtries = Column(Integer, index=False, unique=False)
    cdata = Column(String(50), index=False, unique=False)
    url = Column(String(255), index=False, unique=False)

    def __init__(self, ts, session_id, exception, mdelay, mtries, cdata, url):
        self.ts = ts
        self.session_id = session_id
        self.exception = exception
        self.mdelay = mdelay
        self.mtries = mtries
        self.cdata = cdata
        self.url = url


class Screenshots(Base):
    __tablename__ = 'screenshots'
    id = Column(Integer, primary_key=True)
    ts = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    session_id = Column(Integer, index=True, unique=False)
    error_id = Column(Integer, index=True, unique=False)
    url = Column(String(255), index=False, unique=False)
    
    def __init__(self, ts, session_id, error_id, url):
        self.ts = ts
        self.session_id = session_id
        self.error_id = error_id
        self.url = url


class NetflixVideoDiags(Base):
    __tablename__ = 'nflx_video_diags'
    id = Column(Integer, primary_key=True)
    ts = Column(
        DateTime(timezone=True),
        index=True,
        unique=False,
        server_default=func.now()
    )
    session_id = Column(Integer, index=True, unique=False)
    time_remaining = Column(String(50), index=True, unique=False)
    AudioTrack = Column(String(255), index=True, unique=False)
    Bandwidth_normalized_ = Column(String(255), index=True, unique=False)
    Bufferingbitrate_a_v_ = Column(String(255), index=True, unique=False)
    Bufferingstate = Column(String(255), index=True, unique=False)
    BuffersizeinBytes = Column(String(255), index=True, unique=False)
    BuffersizeinBytes_a_v_ = Column(String(255), index=True, unique=False)
    BuffersizeinSeconds_a_v_ = Column(String(255), index=True, unique=False)
    CurrentCDN_a_v_ = Column(String(255), index=True, unique=False)
    PBCID = Column(String(255), index=True, unique=False)
    CurrentDroppedFrames = Column(String(255), index=True, unique=False)
    DFR = Column(String(255), index=True, unique=False)
    Duration = Column(String(255), index=True, unique=False)
    Esn = Column(String(255), index=True, unique=False)
    Framerate = Column(String(255), index=True, unique=False)
    Latency = Column(String(255), index=True, unique=False)
    MainThreadstall_sec = Column(String(255), index=True, unique=False)
    MaxSustainableVideoBitrate = Column(String(255), index=True, unique=False)
    MovieId = Column(String(255), index=True, unique=False)
    PlayerDuration = Column(String(255), index=True, unique=False)
    Playerstate = Column(String(255), index=True, unique=False)
    Playing_Bufferingvmaf = Column(String(255), index=True, unique=False)
    Playingbitrate_a_v_ = Column(String(255), index=True, unique=False)
    Position = Column(String(255), index=True, unique=False)
    Renderingstate = Column(String(255), index=True, unique=False)
    Throughput = Column(String(255), index=True, unique=False)
    TimedTextTrack = Column(String(255), index=True, unique=False)
    TotalCorruptedFrames = Column(String(255), index=True, unique=False)
    TotalDroppedFrames = Column(String(255), index=True, unique=False)
    TotalFrameDelay = Column(String(255), index=True, unique=False)
    TotalFrames = Column(String(255), index=True, unique=False)
    TrackingId = Column(String(255), index=True, unique=False)
    UserAgent = Column(String(255), index=True, unique=False)
    Version = Column(String(255), index=True, unique=False)
    VideoDiag = Column(String(255), index=True, unique=False)
    VideoTrack = Column(String(255), index=True, unique=False)
    Volume = Column(String(255), index=True, unique=False)
    WillRebuffer = Column(String(255), index=True, unique=False)
    Xid = Column(String(255), index=True, unique=False)
    SegmentPosition = Column(String(255), index=True, unique=False)
    Segment = Column(String(255), index=True, unique=False)
    HDRsupport = Column(String(255), index=True, unique=False)
    KeySystem = Column(String(255), index=True, unique=False)
    KeyStatus = Column(String(255), index=True, unique=False)
    AudioTags = Column(String(255), index=True, unique=False)
    VideoTags = Column(String(255), index=True, unique=False)

    def __init__(
        self,
        ts,
        session_id,
        time_remaining,
        AudioTrack,
        Bandwidth_normalized_,
        Bufferingbitrate_a_v_,
        Bufferingstate,
        BuffersizeinBytes,
        BuffersizeinBytes_a_v_,
        BuffersizeinSeconds_a_v_,
        CurrentCDN_a_v_,
        PBCID,
        CurrentDroppedFrames,
        DFR,
        Duration,
        Esn,
        Framerate,
        Latency,
        MainThreadstall_sec,
        MaxSustainableVideoBitrate,
        MovieId,
        PlayerDuration,
        Playerstate,
        Playing_Bufferingvmaf,
        Playingbitrate_a_v_,
        Position,
        Renderingstate,
        Throughput,
        TimedTextTrack,
        TotalCorruptedFrames,
        TotalDroppedFrames,
        TotalFrameDelay,
        TotalFrames,
        TrackingId,
        UserAgent,
        Version,
        VideoDiag,
        VideoTrack,
        Volume,
        WillRebuffer,
        Xid,
        SegmentPosition,
        Segment,
        HDRsupport,
        KeySystem,
        KeyStatus,
        AudioTags,
        VideoTags
    ):
        self.ts = ts
        self.session_id = session_id
        self.time_remaining = time_remaining
        self.AudioTrack = AudioTrack
        self.Bandwidth_normalized_ = Bandwidth_normalized_
        self.Bufferingbitrate_a_v_ = Bufferingbitrate_a_v_
        self.Bufferingstate = Bufferingstate
        self.BuffersizeinBytes = BuffersizeinBytes
        self.BuffersizeinBytes_a_v_ = BuffersizeinBytes_a_v_
        self.BuffersizeinSeconds_a_v_ = BuffersizeinSeconds_a_v_
        self.CurrentCDN_a_v_ = CurrentCDN_a_v_
        self.PBCID = PBCID
        self.CurrentDroppedFrames = CurrentDroppedFrames
        self.DFR = DFR
        self.Duration = Duration
        self.Esn = Esn
        self.Framerate = Framerate
        self.Latency = Latency
        self.MainThreadstall_sec = MainThreadstall_sec
        self.MaxSustainableVideoBitrate = MaxSustainableVideoBitrate
        self.MovieId = MovieId
        self.PlayerDuration = PlayerDuration
        self.Playerstate = Playerstate
        self.Playing_Bufferingvmaf = Playing_Bufferingvmaf
        self.Playingbitrate_a_v_ = Playingbitrate_a_v_
        self.Position = Position
        self.Renderingstate = Renderingstate
        self.Throughput = Throughput
        self.TimedTextTrack = TimedTextTrack
        self.TotalCorruptedFrames = TotalCorruptedFrames
        self.TotalDroppedFrames = TotalDroppedFrames
        self.TotalFrameDelay = TotalFrameDelay
        self.TotalFrames = TotalFrames
        self.TrackingId = TrackingId
        self.UserAgent = UserAgent
        self.Version = Version
        self.VideoDiag = VideoDiag
        self.VideoTrack = VideoTrack
        self.Volume = Volume
        self.WillRebuffer = WillRebuffer
        self.Xid = Xid
        self.SegmentPosition = SegmentPosition
        self.Segment = Segment
        self.HDRsupport = HDRsupport
        self.KeySystem = KeySystem
        self.KeyStatus = KeyStatus
        self.AudioTags = AudioTags
        self.VideoTags = VideoTags
