# -*- coding: utf-8 -*-

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, create_engine, BigInteger
)

from sqlalchemy.sql import func
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import exc, event, select

from config import (
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_POOL_RECYCLE
)


Base = declarative_base()
engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    pool_recycle=SQLALCHEMY_POOL_RECYCLE
)
session = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
)
session.expire_on_commit = False


@event.listens_for(engine, 'engine_connect')
def ping_connection(connection, branch):
    if branch:
        # "branch" refers to a sub-connection of a connection,
        # we don't want to bother pinging on these.
        return

    # turn off "close with result".  This flag is only used with
    # "connectionless" execution, otherwise will be False in any case
    save_should_close_with_result = connection.should_close_with_result
    connection.should_close_with_result = False

    try:
        # run a SELECT 1.   use a core select() so that
        # the SELECT of a scalar value without a table is
        # appropriately formatted for the backend
        connection.scalar(select([1]))
    except exc.DBAPIError as err:
        # catch SQLAlchemy's DBAPIError, which is a wrapper
        # for the DBAPI's exception.  It includes a .connection_invalidated
        # attribute which specifies if this connection is a "disconnect"
        # condition, which is based on inspection of the original exception
        # by the dialect in use.
        if err.connection_invalidated:
            # run the same SELECT again - the connection will re-validate
            # itself and establish a new connection.  The disconnect detection
            # here also causes the whole connection pool to be invalidated
            # so that all stale connections are discarded.
            connection.scalar(select([1]))
        else:
            raise
    finally:
        # restore "close with result"
        connection.should_close_with_result = save_should_close_with_result


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
        self, dt, guid, type, proto, ip, country, city, conns, weight, bytesin,
        bytesout, status, cipher, auth, upnp, hostapd
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


    def __repr__(
        self, dt, guid, type, proto, ip, country, city, conns, weight, bytesin,
        bytesout, status
    ):
        return(
            '<Device {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}>'.format(
                self.id, self.dt, self.guid, self.type, self.proto, self.ip,
                self.country, self.city, self.conns, self.weight, self.bytesin,
                self.bytesout, self.status, self.cipher, self.auth, self.upnp,
                self.hostapd
            )
        )


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


    def __repr__(self, dt, guid, status, down, up):
        return(
            '<Speedtest {} {} {} {} {}'.format(
                self.id, self.dt, self.guid, self.status, self.down, self.up
            )
        )


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


    def __repr__(self, dt, guid, status, test, result):
        return(
            '<IOTest {} {} {} {} {}'.format(
                self.id,
                self.dt,
                self.guid,
                self.status,
                self.test,
                self.result
                )
            )


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


    def __repr__(
        self, ts, trackingid, provider, email, password, profile,
        switch_profile, titleid, host, tag, tries, attempt, seconds
    ):
        return(
            '<Sessions {} {} {} {} {} {} {} {} {} {} {} {}>'.format(
                self.id, self.ts, self.trackingid, self.provider, self.email,
                self.password, self.profile, self.switch_profile, self.titleid,
                self.host, self.tag, self.tries, self.attempt, self.seconds
            )
        )


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


    def __repr__(self, ts, session_id, exception, mdelay, mtries, cdata, url):
        return(
            '<Errors {} {} {} {} {} {} {} {}>'.format(
                self.id, self.ts, self.session_id, self.exception, self.mdelay,
                self.mtries, self.cdata, self.url
            )
        )


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


    def __repr__(self, ts, session_id, error_id, url):
        return(
            '<Screenshots {} {} {} {} {}>'.format(
                self.id, self.ts, self.session_id, self.error_id, self.url
            )
        )


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


    def __repr__(self):
        return(
            '<nflx_video_diags {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}>'.format(
                self.id,
                self.ts,
                self.session_id,
                self.time_remaining,
                self.AudioTrack,
                self.Bandwidth_normalized_,
                self.Bufferingbitrate_a_v_,
                self.Bufferingstate,
                self.BuffersizeinBytes,
                self.BuffersizeinBytes_a_v_,
                self.BuffersizeinSeconds_a_v_,
                self.CurrentCDN_a_v_,
                self.PBCID,
                self.CurrentDroppedFrames,
                self.DFR,
                self.Duration,
                self.Esn,
                self.Framerate,
                self.Latency,
                self.MainThreadstall_sec,
                self.MaxSustainableVideoBitrate,
                self.MovieId,
                self.PlayerDuration,
                self.Playerstate,
                self.Playing_Bufferingvmaf,
                self.Playingbitrate_a_v_,
                self.Position,
                self.Renderingstate,
                self.Throughput,
                self.TimedTextTrack,
                self.TotalCorruptedFrames,
                self.TotalDroppedFrames,
                self.TotalFrameDelay,
                self.TotalFrames,
                self.TrackingId,
                self.UserAgent,
                self.Version,
                self.VideoDiag,
                self.VideoTrack,
                self.Volume,
                self.WillRebuffer,
                self.Xid,
                self.SegmentPosition,
                self.Segment,
                self.HDRsupport,
                self.KeySystem,
                self.KeyStatus,
                self.AudioTags,
                self.VideoTags
            )
        )
