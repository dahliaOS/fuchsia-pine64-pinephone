// Copyright 2016 The Fuchsia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ddk/protocol/char.h>
#include <ddk/protocol/console.h>
#include <sys/param.h>
#include <font/font.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define VCDEBUG 1

#include "vc.h"
#include "vcdebug.h"

static uint32_t default_palette[] = {
    0xff000000, // black
    0xff0000aa, // blue
    0xff00aa00, // green
    0xff00aaaa, // cyan
    0xffaa0000, // red
    0xffaa00aa, // magenta
    0xffaa5500, // brown
    0xffaaaaaa, // grey
    0xff555555, // dark grey
    0xff5555ff, // bright blue
    0xff55ff55, // bright green
    0xff55ffff, // bright cyan
    0xffff5555, // bright red
    0xffff55ff, // bright magenta
    0xffffff55, // yellow
    0xffffffff, // white
};

#define DEFAULT_FRONT_COLOR 0x0 // black
#define DEFAULT_BACK_COLOR  0xf // white

#define SCROLLBACK_ROWS 1024 // TODO make configurable
#define TOTAL_ROWS(dev) (dev->rows + dev->scrollback_rows)

#define ABS(val) (((val) >= 0) ? (val) : -(val))

static mx_status_t vc_device_setup(vc_device_t *dev) {
    assert(dev->gfx);
    assert(dev->hw_gfx);

    dev->lock = MXR_MUTEX_INIT;

    // calculate how many rows/columns we have
    dev->rows = dev->gfx->height / FONT_Y;
    dev->columns = dev->gfx->width / FONT_X;
    dev->scrollback_rows = SCROLLBACK_ROWS;

    // allocate the text buffer
    dev->text_buf = calloc(1, dev->rows * dev->columns * sizeof(vc_char_t));
    if (!dev->text_buf) return ERR_NO_MEMORY;

    // allocate the scrollback buffer
    dev->scrollback_buf = calloc(1, dev->scrollback_rows * dev->columns * sizeof(vc_char_t));
    if (!dev->scrollback_buf) {
        free(dev->text_buf);
        return ERR_NO_MEMORY;
    }

    // set up the default palette
    memcpy(&dev->palette, default_palette, sizeof(default_palette));
    dev->front_color = DEFAULT_FRONT_COLOR;
    dev->back_color = DEFAULT_BACK_COLOR;

    return NO_ERROR;
}

static void vc_device_invalidate(void* cookie, int x0, int y0, int w, int h) {
    vc_device_t* dev = cookie;
    for (int y = y0; y < y0 + h; y++) {
        int sc = 0;
        if (y < 0) {
            sc = dev->sc_t + y;
            if (sc < 0) sc += dev->scrollback_rows;
        }
        for (int x = x0; x < x0 + w; x++) {
            if (y < 0) {
                vc_gfx_draw_char(dev, dev->scrollback_buf[x + sc * dev->columns], x, y - dev->vpy);
            } else {
                vc_gfx_draw_char(dev, dev->text_buf[x + y * dev->columns], x, y - dev->vpy);
            }
        }
    }
}

// implement tc callbacks:

static void vc_tc_invalidate(void* cookie, int x0, int y0, int w, int h) {
    vc_device_t* dev = cookie;
    if (dev->flags & VC_FLAG_RESETSCROLL) {
        dev->flags &= ~VC_FLAG_RESETSCROLL;
        vc_device_scroll_viewport(dev, -dev->vpy);
    }
    if (dev->vpy < 0) return;
    vc_device_invalidate(cookie, x0, y0, w, h);
    vc_gfx_invalidate(dev, x0, y0, w, h);
}

static void vc_tc_movecursor(void* cookie, int x, int y) {
    vc_device_t* dev = cookie;
    if (!dev->hide_cursor) {
        vc_device_invalidate(cookie, dev->x, dev->y, 1, 1);
        vc_gfx_invalidate(dev, dev->x, dev->y, 1, 1);
        gfx_fillrect(dev->gfx, x * FONT_X, y * FONT_Y, FONT_X, FONT_Y, palette_to_color(dev, dev->front_color));
        vc_gfx_invalidate(dev, x, y, 1, 1);
    }
    dev->x = x;
    dev->y = y;
}

static void vc_tc_pushline(void* cookie, int y) {
    vc_device_t* dev = cookie;
    vc_char_t* dst = &dev->scrollback_buf[dev->sc_t * dev->columns];
    vc_char_t* src = &dev->text_buf[y * dev->columns];
    memcpy(dst, src, dev->columns * sizeof(vc_char_t));
    dev->sc_t += 1;
    if (dev->vpy < 0) dev->vpy -= 1;
    if (dev->sc_t >= dev->scrollback_rows) {
        dev->sc_t -= dev->scrollback_rows;
        if (dev->sc_t >= dev->sc_h) dev->sc_h = dev->sc_t + 1;
    }
}

// positive = up, negative = down
// textbuf must be updated before calling scroll
static void vc_tc_scroll(void* cookie, int y0, int y1, int dir) {
    vc_device_t* dev = cookie;
    if (dev->vpy < 0) return;
    // invalidate the cursor before copying
    vc_device_invalidate(cookie, dev->x, dev->y, 1, 1);
    int delta = ABS(dir);
    if (dir > 0) {
        gfx_copyrect(dev->gfx, 0, (y0 + delta) * FONT_Y, dev->gfx->width, (y1 - y0 - delta) * FONT_Y, 0, y0);
        vc_device_invalidate(cookie, 0, y1 - delta, dev->columns, delta);
    } else {
        gfx_copyrect(dev->gfx, 0, y0, dev->gfx->width, (y1 - y0 - delta) * FONT_Y, 0, (y0 + delta) * FONT_Y);
        vc_device_invalidate(cookie, 0, y0, dev->columns, delta);
    }
    gfx_flush(dev->gfx);
    vc_device_write_status(dev);
    vc_gfx_invalidate_all(dev);
}

static void vc_tc_setparam(void* cookie, int param, uint8_t* arg, size_t arglen) {
    vc_device_t* dev = cookie;
    switch (param) {
        case TC_SET_TITLE:
            strncpy(dev->title, (char*)arg, sizeof(dev->title));
            vc_device_write_status(dev);
            vc_gfx_invalidate_status(dev);
            break;
        case TC_SHOW_CURSOR:
            if (dev->hide_cursor) {
                dev->hide_cursor = false;
                vc_tc_movecursor(dev, dev->x, dev->y);
                gfx_fillrect(dev->gfx, dev->x * FONT_X, dev->y * FONT_Y, FONT_X, FONT_Y, palette_to_color(dev, dev->front_color));
                vc_gfx_invalidate(dev, dev->x, dev->y, 1, 1);
            }
            break;
        case TC_HIDE_CURSOR:
            if (!dev->hide_cursor) {
                dev->hide_cursor = true;
                vc_device_invalidate(cookie, dev->x, dev->y, 1, 1);
                vc_gfx_invalidate(dev, dev->x, dev->y, 1, 1);
            }
        default:
            ; // nothing
    }
}

static void vc_device_reset(vc_device_t *dev) {
    // reset the cursor
    dev->x = 0;
    dev->y = 0;
    // reset the viewport position
    dev->vpy = 0;

    tc_init(&dev->textcon, dev->columns, dev->rows, dev->text_buf, dev->front_color, dev->back_color);
    dev->textcon.cookie = dev;
    dev->textcon.invalidate = vc_tc_invalidate;
    dev->textcon.movecursor = vc_tc_movecursor;
    dev->textcon.pushline = vc_tc_pushline;
    dev->textcon.scroll = vc_tc_scroll;
    dev->textcon.setparam = vc_tc_setparam;

    // fill textbuffer with blank characters
    size_t count = dev->rows * dev->columns;
    vc_char_t* ptr = dev->text_buf;
    while (count--) {
        *ptr++ = CHARVAL(' ', dev->front_color, dev->back_color);
    }

    // fill screen with back color
    gfx_fillrect(dev->gfx, 0, 0, dev->gfx->width, dev->gfx->height, palette_to_color(dev, dev->back_color));
    gfx_flush(dev->gfx);

    vc_gfx_invalidate_all(dev);
}

void vc_device_write_status(vc_device_t* dev) {
    static enum { NORMAL, ESCAPE } state = NORMAL;
    int fg = 7;
    int bg = 0;
    char c, str[512];
    int idx = 0;
    int p_num = 0;
    vc_get_status_line(str, sizeof(str));
    // TODO clean this up with textcon stuff
    gfx_fillrect(dev->st_gfx, 0, 0, dev->st_gfx->width, dev->st_gfx->height, palette_to_color(dev, bg));
    for (uint i = 0; i < MIN(dev->columns, strlen(str)); i++) {
        c = str[i];
        if (state == NORMAL) {
            if (c == 0x1b) {
                state = ESCAPE;
                p_num = 0;
            } else {
                font_draw_char(dev->st_gfx, c, idx++ * FONT_X, 0, palette_to_color(dev, fg), palette_to_color(dev, bg));
            }
        } else if (state == ESCAPE) {
            if (c >= '0' && c <= '9') {
                p_num = (p_num * 10) + (c - '0');
            } else if (c == 'm') {
                if (p_num >= 30 && p_num <= 37) {
                    fg = p_num - 30;
                } else if (p_num >= 40 && p_num <= 47) {
                    bg = p_num - 40;
                } else if (p_num == 1 && fg <= 0x7) {
                    fg += 8;
                } else if (p_num == 0) {
                    fg = 7;
                    bg = 0;
                }
                state = NORMAL;
            } else {
                // eat unrecognized escape sequences in status
            }
        }
    }
    gfx_flush(dev->st_gfx);
}

void vc_device_render(vc_device_t* dev) {
    vc_device_write_status(dev);
    vc_gfx_invalidate_all(dev);
}

int vc_device_get_scrollback_lines(vc_device_t* dev) {
     return dev->sc_t >= dev->sc_h ? dev->sc_t - dev->sc_h : dev->scrollback_rows - 1;
}

void vc_device_scroll_viewport(vc_device_t* dev, int dir) {
    int vpy = MAX(MIN(dev->vpy + dir, 0), -vc_device_get_scrollback_lines(dev));
    int delta = ABS(dev->vpy - vpy);
    if (delta == 0) return;
    dev->vpy = vpy;
    if (dir > 0) {
        gfx_copyrect(dev->gfx, 0, delta * FONT_Y, dev->gfx->width, (dev->rows - delta) * FONT_Y, 0, 0);
        vc_device_invalidate(dev, 0, vpy + dev->rows - delta, dev->columns, delta);
    } else {
        gfx_copyrect(dev->gfx, 0, 0, dev->gfx->width, (dev->rows - delta) * FONT_Y, 0, delta * FONT_Y);
        vc_device_invalidate(dev, 0, vpy, dev->columns, delta);
    }
    gfx_flush(dev->gfx);
    vc_device_write_status(dev);
    vc_gfx_invalidate_all(dev);
}

static mx_protocol_char_t vc_char_proto = {
    .read = vc_char_read,
    .write = vc_char_write,
    .ioctl = vc_char_ioctl,
};

static mx_protocol_console_t vc_console_proto = {
    .getsurface = vc_console_getsurface,
    .invalidate = vc_console_invalidate,
    .movecursor = vc_console_movecursor,
    .setpalette = vc_console_setpalette,
    .readkey = vc_console_readkey,
};

// implement device protocol

mx_status_t vc_device_get_protocol(mx_device_t* dev, uint32_t protocol_id, void** protocol) {
    switch (protocol_id) {
        case MX_PROTOCOL_CHAR:
            *protocol = &vc_char_proto;
            break;
        case MX_PROTOCOL_CONSOLE:
            *protocol = &vc_console_proto;
            break;
        default:
            return ERR_NOT_SUPPORTED;
    }
    return NO_ERROR;
}

mx_status_t vc_device_open(mx_device_t* dev, uint32_t flags) {
    return NO_ERROR;
}

mx_status_t vc_device_close(mx_device_t* dev) {
    return NO_ERROR;
}

mx_status_t vc_device_release(mx_device_t* dev) {
    return NO_ERROR;
}

mx_protocol_device_t vc_device_proto = {
    .get_protocol = vc_device_get_protocol,
    .open = vc_device_open,
    .close = vc_device_close,
    .release = vc_device_release,
};

mx_status_t vc_device_alloc(gfx_surface *hw_gfx, vc_device_t** out_dev) {
    vc_device_t* device = calloc(1, sizeof(vc_device_t));
    if (!device) return ERR_NO_MEMORY;

    // init the status bar
    device->st_gfx = gfx_create_surface(NULL, hw_gfx->width, FONT_Y, hw_gfx->stride, hw_gfx->format, 0);
    if (!device->st_gfx) goto fail;

    // init the main surface
    device->gfx = gfx_create_surface(NULL, hw_gfx->width, hw_gfx->height - FONT_Y, hw_gfx->stride, hw_gfx->format, 0);
    if (!device->gfx) goto fail;
    device->hw_gfx = hw_gfx;

    vc_device_setup(device);
    vc_device_reset(device);

    *out_dev = device;
    return NO_ERROR;
fail:
    if (device->st_gfx) gfx_surface_destroy(device->st_gfx);
    free(device);
    return ERR_NO_MEMORY;
}
