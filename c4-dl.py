import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import struct
import sys
import xml.etree.ElementTree as ET
import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pywidevine.pssh import PSSH
from pywidevine.device import Device
from pywidevine.cdm import Cdm
from globals import DEFAULT_HEADERS, DOWNLOAD_DIR, MPD_HEADERS, TMP_DIR  # pylint: disable=no-name-in-module

_script_dir = os.path.dirname(os.path.realpath(__file__))
_proto_path = os.path.join(_script_dir, 'generated')

sys.path.insert(0, _proto_path)
# pylint: disable=wrong-import-position, wrong-import-order, import-error
import widevine_pssh_data_pb2 as widevine  # nopep8


class ComplexJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, 'to_json'):
            return o.to_json()
        return json.JSONEncoder.default(self, o)


class Video:
    def __init__(self, video_type: str, url: str):
        self.video_type = video_type
        self.url = url

    def to_json(self):
        resp = {}

        if self.video_type != "":
            resp['type'] = self.video_type
        if self.url != "":
            resp['url'] = self.url
        return resp


class DrmToday:
    def __init__(self, request_id: str, token: str, video: Video, message: str):
        self.request_id = request_id
        self.token = token
        self.video = video
        self.message = message

    def to_json(self):
        resp = {}

        if self.request_id != "":
            resp['request_id'] = self.request_id
        if self.token != "":
            resp['token'] = self.token
        if self.video != "":
            resp['video'] = self.video
        if self.message != "":
            resp['message'] = self.message
        return resp


class Status:
    def __init__(self, success: bool, status_type: str):
        self.success = success
        self.status_type = status_type


class VodConfig:
    def __init__(self, vodbs_url: str, drm_today: DrmToday, message: str):
        self.vodbs_url = vodbs_url
        self.drm_today = drm_today
        self.message = message


class VodStream:
    def __init__(self, token: str, uri: str, brand_title: str, episode_title: str):
        self.token = token
        self.uri = uri
        self.brand_title = brand_title
        self.episode_title = episode_title

    def to_json(self):
        resp = {}

        if self.token != "":
            resp['token'] = self.token
        if self.uri != "":
            resp['uri'] = self.uri
        return resp


class LicenseResponse:
    def __init__(self, license_response: str, status: Status):
        self.license_response = license_response
        self.status = status

    def to_json(self):
        resp = {}

        if self.license_response != "":
            resp['license'] = self.license_response
        if self.status != "":
            resp['status'] = self.status
        return resp


def decrypt_token(token: str):
    try:
        cipher = AES.new(
            b"\x41\x59\x44\x49\x44\x38\x53\x44\x46\x42\x50\x34\x4d\x38\x44\x48",
            AES.MODE_CBC,
            b"\x31\x44\x43\x44\x30\x33\x38\x33\x44\x4b\x44\x46\x53\x4c\x38\x32"
        )
        decoded_token = base64.b64decode(token)
        decrypted_string = unpad(cipher.decrypt(
            decoded_token), 16, style='pkcs7').decode('UTF-8')
        license_info = decrypted_string.split('|')
        return VodStream(license_info[1], license_info[0], '', '')
    except:  # pylint:disable=bare-except
        print('[!] Failed decrypting VOD stream !!!')
        raise


def get_vod_stream(asset_id: str):
    try:
        url = f'https://ais.channel4.com/asset/{asset_id}?client=android-mod'
        req = requests.get(url)
        if req.status_code == requests.codes['not_found']:
            print('[!] Invalid URL !!!')
            sys.exit(1)

        req.raise_for_status

        root = ET.fromstring(req.content)
        asset_info_xpath = './assetInfo/'

        brand_title = root.find(asset_info_xpath + 'brandTitle').text
        brand_title = brand_title.replace(':', ' ')
        brand_title = brand_title.replace('/', ' ')

        episode_title = root.find(asset_info_xpath + 'episodeTitle').text
        episode_title = episode_title.replace(':', ' ')
        episode_title = episode_title.replace('/', ' ')

        stream_xpath = f'{asset_info_xpath}videoProfiles/videoProfile[@name=\'widevine-stream-4\']/stream/'
        uri = root.find(stream_xpath + 'uri').text
        token = root.find(stream_xpath + 'token').text

        vod_stream = VodStream(token, uri, brand_title, episode_title)

        return vod_stream
    except:  # pylint:disable=bare-except
        print('[!] Failed getting VOD stream !!!')
        raise


def get_asset_id(url: str):
    try:
        req = requests.get(url)
        req.raise_for_status
        init_data = re.search(
            '<script>window\.__PARAMS__ = (.*)</script>',
            ''.join(
                req.content.decode()
                .replace('\u200c', '')
                .replace('\r\n', '')
                .replace('undefined', 'null')
            )
        )
        init_data = json.loads(init_data.group(1))
        asset_id = int(init_data['initialData']['selectedEpisode']['assetId'])

        if asset_id == 0:
            raise  # pylint: disable=misplaced-bare-raise
        return asset_id
    except:  # pylint:disable=bare-except
        print('[!] Failed getting asset ID !!!')
        raise


def get_config():
    try:
        req = requests.get(
            'https://static.c4assets.com/all4-player/latest/bundle.app.js')
        req.raise_for_status
        configs = re.findall(
            "JSON\.parse\(\'(.*?)\'\)",
            ''.join(
                req.content.decode()
                .replace('\u200c', '')
                .replace('\\"', '\"')
            )
        )
        config = json.loads(configs[1])
        video_type = config['protectionData']['com.widevine.alpha']['drmtoday']['video']['type']
        message = config['protectionData']['com.widevine.alpha']['drmtoday']['message']
        video = Video(video_type, '')
        drm_today = DrmToday('', '', video, message)
        vod_config = VodConfig(config['vodbsUrl'], drm_today, '')
        return vod_config
    except:  # pylint:disable=bare-except
        print('[!] Failed getting production config !!!')
        raise


def get_service_certificate(url: str, drm_today: DrmToday):
    try:
        req = requests.post(url, data=json.dumps(
            drm_today.to_json(), cls=ComplexJsonEncoder), headers=DEFAULT_HEADERS)
        req.raise_for_status
        resp = json.loads(req.content)
        license_response = resp['license']
        status = Status(resp['status']['success'], resp['status']['type'])
        return LicenseResponse(license_response, status)
    except:  # pylint:disable=bare-except
        print('[!] Failed getting signed DRM certificate !!!')
        raise


def get_license_response(url: str, drm_today: DrmToday):
    try:
        req = requests.post(url, data=json.dumps(
            drm_today.to_json(), cls=ComplexJsonEncoder), headers=DEFAULT_HEADERS)
        req.raise_for_status
        resp = json.loads(req.content)
        license_response = resp['license']
        status = Status(resp['status']['success'], resp['status']['type'])

        if not status.success:
            raise  # pylint:disable=misplaced-bare-raise
        return LicenseResponse(license_response, status)
    except:  # pylint:disable=bare-except
        print('[!] Failed getting license challenge !!!')
        raise


def get_kid(url: str):
    try:
        req = requests.get(url, headers=MPD_HEADERS)
        req.raise_for_status
        kid = re.search('cenc:default_KID="(.*)"', req.text).group(1)
        return kid
    except:  # pylint:disable=bare-except
        print('[!] Failed getting KID !!!')
        raise


def generate_pssh(kid: str):
    try:
        wide_vine = widevine.WidevinePsshData()
        # pylint: disable=no-member
        wide_vine.key_id.append(base64.b16decode(kid.replace('-', '')))
        wide_vine.provider = 'rbmch4tv'
        wide_vine.content_id = bytes(kid, 'UTF-8')
        wide_vine.policy = ''
        wide_vine.algorithm = 1
        pssh_data = wide_vine.SerializeToString()

        ret = b'pssh' + struct.pack('>i', 0 << 24)
        ret += base64.b16decode('EDEF8BA979D64ACEA3C827DCD51D21ED')
        ret += struct.pack('>i', len(pssh_data))
        ret += pssh_data
        pssh = struct.pack('>i', len(ret) + 4) + ret
        return base64.b64encode(pssh).decode()
    except:  # pylint:disable=bare-except
        print('[!] Failed generating PSSH !!!')
        raise


def get_file_output_title(brand_title: str, episode_title: str):
    try:
        title = re.search('^Series\s+(\d+)\s+Episode\s+(\d+)$', episode_title)
        if title is None:
            output_title = f'{brand_title} {episode_title} WEB-DL'
            output_title = ' '.join(output_title.split())
            return output_title.replace(' ', '.')
        series = title.group(1)
        episode = title.group(2)

        if len(series) == 1:
            series = '0' + series
        if len(episode) == 1:
            episode = '0' + episode

        output_title = f'{brand_title} S{series}E{episode} WEB-DL'
        output_title = ' '.join(output_title.split())
        return output_title.replace(' ', '.')
    except:  # pylint:disable=bare-except
        print('[!] Failed getting output title !!!')
        raise


def download_streams(mpd: str, output_title: str):
    try:
        args = [
            './bin/yt-dlp.exe',
            '--downloader',
            'aria2c',
            '--allow-unplayable-formats',
            '-q',
            '--no-warnings',
            '--progress',
            '-f',
            'bv,wa', # Prevent audo description
            mpd,
            '-o',
            f'{TMP_DIR}/{output_title}/encrypted_{output_title}.%(height)sp.%(vcodec)s%(acodec)s.%(ext)s'
        ]
        subprocess.run(args, check=True)
    except:  # pylint:disable=bare-except
        print('[!] Failed downloading streams !!!')
        raise


def decrypt_streams(decryption_key: str, output_title: str):
    try:
        files = []
        for file in os.listdir(f'{TMP_DIR}/{output_title}'):
            if output_title in file:
                input_file = f'{TMP_DIR}/{output_title}/{file}'
                file = file.replace('encrypted_', 'decrypted_')
                output_file = f'{TMP_DIR}/{output_title}/{file}'
                files.append(output_file)
                args = [
                    './bin/mp4decrypt.exe',
                    '--key',
                    decryption_key,
                    input_file,
                    output_file
                ]
                subprocess.run(args, check=True)
        return files
    except:  # pylint:disable=bare-except
        print('[!] Failed decrypting streams !!!')
        raise


def get_audio_codec(file_name: str):
    aac_codec = 'mp4a.40'
    ac3_codec = 'ac-3'
    mp3_codec = 'mp4a.6'
    if aac_codec in file_name:
        return 'AAC'
    if mp3_codec in file_name:
        return 'MP3'
    if ac3_codec in file_name:
        return 'AC-3'
    return ''


def get_video_codec(file_name: str):
    h_264 = 'avc1.'
    h_265 = 'hev1.1'
    if h_264 in file_name:
        return 'H.264'
    if h_265 in file_name:
        return 'H.265'
    return ''


def get_resolution(file_name: str):
    high_quality = '1080p'
    med_quality = '720p'
    low_quality = '420p'
    if high_quality in file_name:
        return high_quality
    if med_quality in file_name:
        return med_quality
    if low_quality in file_name:
        return low_quality
    return ''


def merge_streams(files: list, output_title: str):
    try:
        video_codec = 'unknown'
        audio_codec = 'unknown'
        resolution = 'unknown'

        for file in files:
            a_codec = get_audio_codec(file)
            if a_codec:
                audio_codec = a_codec
            v_codec = get_video_codec(file)
            if v_codec:
                video_codec = v_codec
            v_resolution = get_resolution(file)
            if v_resolution:
                resolution = v_resolution

        output_dir = f'{DOWNLOAD_DIR}/{output_title}.{resolution}.{video_codec}.{audio_codec}'
        # This should check for the correct ext.
        output_file = f'{output_dir}/{output_title}.{resolution}.{video_codec}.{audio_codec}.mp4'

        os.mkdir(output_dir)

        args = [
            './bin/ffmpeg.exe',
            '-hide_banner',
            '-loglevel',
            'error',
            '-i',
            files[0],
            '-i',
            files[1],
            '-c',
            'copy',
            output_file
        ]
        subprocess.run(args, check=True)

        shutil.rmtree(f'{TMP_DIR}/{output_title}')
    except:  # pylint:disable=bare-except
        print('[!] Failed merging streams !!!')
        raise


def create_argument_parser():
    parser = argparse.ArgumentParser(description='Channel 4 downloader.')
    parser.add_argument(
        '--download',
        help='Download the episode',
        action='store_true'
    )
    parser.add_argument(
        '--wvd',
        help='The file path to the WVD file generated by pywidevine'
    )
    parser.add_argument(
        '--url',
        help='The URL of the episode to download'
    )
    args = parser.parse_args()

    if not args.wvd or not args.url:
        parser.print_help()
        sys.exit(1)
    return args


def main():
    parser = create_argument_parser()
    wvd = parser.wvd
    url = parser.url
    download = parser.download

    # Get the prod config
    config = get_config()

    # Get asset ID
    asset_id = get_asset_id(url)

    # Get the MPD and encrypted stream token
    encrypted_vod_stream = get_vod_stream(asset_id)

    # Decrypt the stream token
    decrypted_vod_stream = decrypt_token(encrypted_vod_stream.token)

    # Setup the initial license request
    config.drm_today.video.url = encrypted_vod_stream.uri  # MPD
    config.drm_today.token = decrypted_vod_stream.token  # Decrypted Token
    config.drm_today.request_id = asset_id  # Video asset ID

    # Get the SignedDrmCertificate (common privacy cert)
    service_cert = get_service_certificate(
        decrypted_vod_stream.uri, config.drm_today).license_response

    # Load the WVD and generate a session ID
    device = Device.load(wvd)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    cdm.set_service_certificate(session_id, service_cert)

    # Get license challenge
    kid = get_kid(config.drm_today.video.url)

    # Generate the PSSH
    pssh = generate_pssh(kid)

    challenge = cdm.get_license_challenge(
        session_id, PSSH(pssh), privacy_mode=True)
    config.drm_today.message = base64.b64encode(challenge).decode('UTF-8')

    # Get license response
    license_response = get_license_response(
        decrypted_vod_stream.uri, config.drm_today)

    # Parse license challenge
    cdm.parse_license(session_id, license_response.license_response)

    terminal_size = os.get_terminal_size().columns
    print('*' * terminal_size)
    print(f'[  URL  ] {url}')

    decryption_key = ''

    # Return keys
    for key in cdm.get_keys(session_id):
        if key.type == 'CONTENT':
            decryption_key = f'{key.kid.hex}:{key.key.hex()}'
            print(f'[{key.type}] {key.kid.hex}:{key.key.hex()}')

    print(f'[  MPD  ] {config.drm_today.video.url}')
    print('*' * terminal_size)

    # Close session, disposes of session data
    cdm.close(session_id)

    if download:
        output_title = get_file_output_title(
            encrypted_vod_stream.brand_title, encrypted_vod_stream.episode_title)
        download_streams(config.drm_today.video.url, output_title)
        files = decrypt_streams(decryption_key, output_title)
        merge_streams(files, output_title)


if __name__ == '__main__':
    main()
